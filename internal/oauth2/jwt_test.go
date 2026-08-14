package oauth2

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestSignJWT(t *testing.T) {
	key, err := ReadKey(SigningKey, "../../data/rsa/key.json", http.DefaultClient)
	noErr(t, err)

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
	noErr(t, err)

	jws, err := jose.ParseSigned(token, JOSESignatureAlgorithms)
	noErr(t, err)

	bs, err := jws.Verify(key.Public())
	noErr(t, err)

	m := map[string]interface{}{}

	err = json.Unmarshal(bs, &m)
	noErr(t, err)

	eq(t, "jdoe@example.com", m["sub"].(string))
	notEmpty(t, m["aud"].(string))
	notEmpty(t, m["iss"].(string))
	notEmpty(t, m["jti"].(string))
}

func TestVerifyIDTokenWithNonce(t *testing.T) {
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
		noErr(t, err)

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
		noErr(t, err)

		return token
	}

	signHMAC := func(t *testing.T, claims map[string]interface{}, secret []byte) string {
		t.Helper()

		token, _, err := SignJWT(func() (map[string]interface{}, error) {
			return claims, nil
		}, SecretSigner(secret))
		noErr(t, err)

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
		got, checks, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(nil)), "", sconfig, cconfig, hc)
		noErr(t, err)
		empty(t, got)
		eq(t, checkResult(t, checks, "id_token.nonce"), CheckSkip)
	})

	t.Run("skip when id token empty", func(t *testing.T) {
		got, checks, err := VerifyIDTokenWithNonce("", expected, sconfig, cconfig, hc)
		noErr(t, err)
		empty(t, got)
		eq(t, checkResult(t, checks, "id_token.nonce"), CheckSkip)
	})

	t.Run("matching nonce", func(t *testing.T) {
		got, checks, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(nil)), expected, sconfig, cconfig, hc)
		noErr(t, err)
		eq(t, expected, got)
		eq(t, checkResult(t, checks, "id_token.nonce"), CheckPass)
		eq(t, checkResult(t, checks, "id_token.extra_audiences"), CheckPass)
		eq(t, checkResult(t, checks, "id_token.azp"), CheckPass)
	})

	t.Run("matching nonce without kid", func(t *testing.T) {
		got, _, err := VerifyIDTokenWithNonce(signRSAWithoutKID(t, validClaims(nil)), expected, sconfig, cconfig, hc)
		noErr(t, err)
		eq(t, expected, got)
	})

	t.Run("no kid with multiple signing keys", func(t *testing.T) {
		key, err := ReadKey(SigningKey, "../../data/rsa/public.json", http.DefaultClient)
		noErr(t, err)

		other := key
		other.KeyID = "other"
		body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key, other}})
		noErr(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		_, _, err = VerifyIDTokenWithNonce(signRSAWithoutKID(t, validClaims(nil)), expected, ServerConfig{
			JWKsURI: srv.URL,
			Issuer:  issuer,
		}, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "multiple signing keys")
	})

	t.Run("mismatched nonce", func(t *testing.T) {
		got, _, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"nonce": "other"})), expected, sconfig, cconfig, hc)
		errorIs(t, err, ErrIDTokenNonceMismatch)
		eq(t, "other", got)
	})

	t.Run("missing nonce", func(t *testing.T) {
		_, _, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"nonce": nil})), expected, sconfig, cconfig, hc)
		errorIs(t, err, ErrIDTokenNonceMissing)
	})

	t.Run("wrong issuer", func(t *testing.T) {
		_, _, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"iss": "https://other.example"})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "id token claims are invalid")
	})

	t.Run("wrong audience", func(t *testing.T) {
		_, _, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"aud": "other-client"})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "id token claims are invalid")
	})

	t.Run("expired", func(t *testing.T) {
		_, _, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"exp": now.Add(-time.Hour).Unix()})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "id token claims are invalid")
	})

	t.Run("missing exp", func(t *testing.T) {
		_, _, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"exp": nil})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "exp claim is missing")
	})

	t.Run("missing iat", func(t *testing.T) {
		_, _, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"iat": nil})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "iat claim is missing")
	})

	t.Run("forged token is rejected", func(t *testing.T) {
		forged := signHMAC(t, validClaims(nil), []byte("test-secret-that-is-long-enough-for-hs256"))

		_, unsafeClaims, err := UnsafeParseJWT(forged)
		noErr(t, err)
		eq(t, expected, unsafeClaims["nonce"])

		_, checks, err := VerifyIDTokenWithNonce(forged, expected, sconfig, cconfig, hc)
		isErr(t, err)
		notErrorIs(t, err, ErrIDTokenNonceMismatch)
		notErrorIs(t, err, ErrIDTokenNonceMissing)
		eq(t, checkResult(t, checks, "id_token.nonce"), CheckSkip)
	})

	t.Run("hmac signature", func(t *testing.T) {
		secret := []byte("test-secret-that-is-long-enough-for-hs256")
		token := signHMAC(t, validClaims(nil), secret)

		got, _, err := VerifyIDTokenWithNonce(token, expected, ServerConfig{Issuer: issuer}, ClientConfig{
			IssuerURL:    issuer,
			ClientID:     clientID,
			ClientSecret: string(secret),
		}, hc)
		noErr(t, err)
		eq(t, expected, got)
	})

	t.Run("untrusted extra audience", func(t *testing.T) {
		_, checks, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{
			"aud": []string{clientID, "https://other.example"},
			"azp": clientID,
		})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "untrusted additional audiences")
		eq(t, checkResult(t, checks, "id_token.aud"), CheckPass)
		eq(t, checkResult(t, checks, "id_token.extra_audiences"), CheckFail)
		eq(t, checkResult(t, checks, "id_token.azp"), CheckPass)
		eq(t, checkResult(t, checks, "id_token.nonce"), CheckPass)
	})

	t.Run("azp mismatch", func(t *testing.T) {
		_, checks, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{"azp": "other-client"})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		contains(t, err.Error(), "azp")
		eq(t, checkResult(t, checks, "id_token.azp"), CheckFail)
	})

	t.Run("multiple audiences require azp", func(t *testing.T) {
		_, checks, err := VerifyIDTokenWithNonce(signRSA(t, validClaims(map[string]interface{}{
			"aud": []string{clientID, "https://other.example"},
		})), expected, sconfig, cconfig, hc)
		isErr(t, err)
		eq(t, checkResult(t, checks, "id_token.extra_audiences"), CheckFail)
		eq(t, checkResult(t, checks, "id_token.azp"), CheckFail)
	})
}

func checkResult(t *testing.T, checks []Verification, name string) string {
	t.Helper()
	for _, check := range checks {
		if check.Name == name {
			return check.Result
		}
	}
	t.Fatalf("missing check %s", name)
	return ""
}
