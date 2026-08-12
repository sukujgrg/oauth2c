package oauth2

import (
	"encoding/json"
	"net/http"
	"testing"

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

	jwt, _, err := SignJWT(claims, JWKSigner("../../data/rsa/key.json", http.DefaultClient))
	require.NoError(t, err)

	jws, err := jose.ParseSigned(jwt, JOSESignatureAlgorithms)
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

func TestIDTokenNonce(t *testing.T) {
	sign := func(t *testing.T, claims map[string]interface{}) string {
		t.Helper()

		token, _, err := SignJWT(func() (map[string]interface{}, error) {
			return claims, nil
		}, SecretSigner([]byte("test-secret-that-is-long-enough-for-hs256")))
		require.NoError(t, err)

		return token
	}

	t.Run("empty token", func(t *testing.T) {
		got, err := IDTokenNonce("")
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("matching nonce", func(t *testing.T) {
		got, err := IDTokenNonce(sign(t, map[string]interface{}{"nonce": "n-0S6_WzA2Mj"}))
		require.NoError(t, err)
		require.Equal(t, "n-0S6_WzA2Mj", got)
	})

	t.Run("missing nonce", func(t *testing.T) {
		got, err := IDTokenNonce(sign(t, map[string]interface{}{"sub": "user"}))
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := IDTokenNonce("not-a-jwt")
		require.Error(t, err)
	})
}
