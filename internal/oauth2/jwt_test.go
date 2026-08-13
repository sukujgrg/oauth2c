package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func TestSignJWT(t *testing.T) {
	key, err := ReadKey(SigningKey, "../../data/rsa/key.json", http.DefaultClient)
	require.NoError(t, err)

	claims := AssertionClaims(
		ServerConfig{
			TokenEndpoint: "https://example.com/tid/aid/oauth2/token",
		},
		ClientConfig{
			IssuerURL: "https://example.com/tid/aid",
			Assertion: `{"sub": "jdoe@example.com"}`,
		},
	)

	token, _, err := SignJWT(claims, JWKSigner("../../data/rsa/key.json", http.DefaultClient))
	require.NoError(t, err)

	jws, err := jose.ParseSigned(token, JOSESignatureAlgorithms)
	require.NoError(t, err)

	bs, err := jws.Verify(key.Public())
	require.NoError(t, err)

	m := map[string]interface{}{}

	err = json.Unmarshal(bs, &m)
	require.NoError(t, err)

	require.Equal(t, "jdoe@example.com", m["sub"].(string))
	require.NotEmpty(t, m["aud"].(string))
	require.NotEmpty(t, m["iss"].(string))
	require.NotEmpty(t, m["jti"].(string))
}

func TestCheckIDTokenNonce(t *testing.T) {
	const (
		expected = "n-0S6_WzA2Mj"
		issuer   = "https://example.com/tid/aid"
		clientID = "test-client"
	)

	now := time.Now()
	validClaims := func(overrides map[string]interface{}) map[string]interface{} {
		claims := map[string]interface{}{
			"iss":   issuer,
			"aud":   clientID,
			"iat":   now.Unix(),
			"exp":   now.Add(time.Minute).Unix(),
			"nonce": expected,
		}
		for k, v := range overrides {
			if v == nil {
				delete(claims, k)
				continue
			}
			claims[k] = v
		}
		return claims
	}

	signRSA := func(t *testing.T, claims map[string]interface{}) string {
		t.Helper()

		token, _, err := SignJWT(func() (map[string]interface{}, error) {
			return claims, nil
		}, JWKSigner("../../data/rsa/key.json", http.DefaultClient))
		require.NoError(t, err)

		return token
	}

	signRSAWithoutKID := func(t *testing.T, claims map[string]interface{}) string {
		t.Helper()

		token, _, err := SignJWT(func() (map[string]interface{}, error) {
			return claims, nil
		}, func() (jose.Signer, interface{}, error) {
			key, err := ReadKey(SigningKey, "../../data/rsa/key.json", http.DefaultClient)
			if err != nil {
				return nil, nil, err
			}

			signer, err := jose.NewSigner(jose.SigningKey{
				Algorithm: jose.SignatureAlgorithm(key.Algorithm),
				Key:       key.Key,
			}, nil)
			return signer, key.Key, err
		})
		require.NoError(t, err)

		return token
	}

	signHMAC := func(t *testing.T, claims map[string]interface{}, secret []byte) string {
		t.Helper()

		token, _, err := SignJWT(func() (map[string]interface{}, error) {
			return claims, nil
		}, SecretSigner(secret))
		require.NoError(t, err)

		return token
	}

	sconfig := ServerConfig{
		JWKsURI: "../../data/rsa/public.json",
		Issuer:  issuer,
	}
	cconfig := ClientConfig{
		IssuerURL: issuer,
		ClientID:  clientID,
	}
	hc := http.DefaultClient

	t.Run("skip when expected empty", func(t *testing.T) {
		got, err := CheckIDTokenNonce("ignored", "", sconfig, cconfig, hc)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("skip when id token empty", func(t *testing.T) {
		got, err := CheckIDTokenNonce("", expected, sconfig, cconfig, hc)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("matching nonce", func(t *testing.T) {
		got, err := CheckIDTokenNonce(signRSA(t, validClaims(nil)), expected, sconfig, cconfig, hc)
		require.NoError(t, err)
		require.Equal(t, expected, got)
	})

	t.Run("matching nonce without kid", func(t *testing.T) {
		got, err := CheckIDTokenNonce(signRSAWithoutKID(t, validClaims(nil)), expected, sconfig, cconfig, hc)
		require.NoError(t, err)
		require.Equal(t, expected, got)
	})

	t.Run("no kid with multiple signing keys", func(t *testing.T) {
		key, err := ReadKey(SigningKey, "../../data/rsa/public.json", http.DefaultClient)
		require.NoError(t, err)

		other := key
		other.KeyID = "other"
		body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key, other}})
		require.NoError(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		_, err = CheckIDTokenNonce(signRSAWithoutKID(t, validClaims(nil)), expected, ServerConfig{
			JWKsURI: srv.URL,
			Issuer:  issuer,
		}, cconfig, hc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple signing keys")
	})

	t.Run("mismatched nonce", func(t *testing.T) {
		got, err := CheckIDTokenNonce(signRSA(t, validClaims(map[string]interface{}{"nonce": "other"})), expected, sconfig, cconfig, hc)
		require.ErrorIs(t, err, ErrIDTokenNonceMismatch)
		require.Equal(t, "other", got)
	})

	t.Run("missing nonce", func(t *testing.T) {
		_, err := CheckIDTokenNonce(signRSA(t, validClaims(map[string]interface{}{"nonce": nil})), expected, sconfig, cconfig, hc)
		require.ErrorIs(t, err, ErrIDTokenNonceMissing)
	})

	t.Run("wrong issuer", func(t *testing.T) {
		_, err := CheckIDTokenNonce(signRSA(t, validClaims(map[string]interface{}{"iss": "https://other.example"})), expected, sconfig, cconfig, hc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id token claims are invalid")
	})

	t.Run("wrong audience", func(t *testing.T) {
		_, err := CheckIDTokenNonce(signRSA(t, validClaims(map[string]interface{}{"aud": "other-client"})), expected, sconfig, cconfig, hc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id token claims are invalid")
	})

	t.Run("expired", func(t *testing.T) {
		_, err := CheckIDTokenNonce(signRSA(t, validClaims(map[string]interface{}{"exp": now.Add(-time.Hour).Unix()})), expected, sconfig, cconfig, hc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "id token claims are invalid")
	})

	t.Run("missing exp", func(t *testing.T) {
		_, err := CheckIDTokenNonce(signRSA(t, validClaims(map[string]interface{}{"exp": nil})), expected, sconfig, cconfig, hc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exp claim is missing")
	})

	t.Run("missing iat", func(t *testing.T) {
		_, err := CheckIDTokenNonce(signRSA(t, validClaims(map[string]interface{}{"iat": nil})), expected, sconfig, cconfig, hc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iat claim is missing")
	})

	t.Run("forged token is rejected", func(t *testing.T) {
		forged := signHMAC(t, validClaims(nil), []byte("test-secret-that-is-long-enough-for-hs256"))

		_, unsafeClaims, err := UnsafeParseJWT(forged)
		require.NoError(t, err)
		require.Equal(t, expected, unsafeClaims["nonce"])

		_, err = CheckIDTokenNonce(forged, expected, sconfig, cconfig, hc)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrIDTokenNonceMismatch)
		require.NotErrorIs(t, err, ErrIDTokenNonceMissing)
	})

	t.Run("hmac signature", func(t *testing.T) {
		secret := []byte("test-secret-that-is-long-enough-for-hs256")
		token := signHMAC(t, validClaims(nil), secret)

		got, err := CheckIDTokenNonce(token, expected, ServerConfig{Issuer: issuer}, ClientConfig{
			IssuerURL:    issuer,
			ClientID:     clientID,
			ClientSecret: string(secret),
		}, hc)
		require.NoError(t, err)
		require.Equal(t, expected, got)
	})
}
