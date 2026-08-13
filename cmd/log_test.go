package cmd

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/sukujgrg/oauth2c/internal/oauth2"
	"github.com/go-jose/go-jose/v4"
)

func TestLogAccessTokenPayload(t *testing.T) {
	t.Run("opaque token", func(t *testing.T) {
		output := captureLogOutput(t)

		LogTokenPayload(oauth2.TokenResponse{AccessToken: "opaque-access-token"})

		contains(t, output.String(), "access_token: (opaque)")
		notContains(t, output.String(), "ERROR")
		notContains(t, output.String(), "compact JWS")
	})

	t.Run("signed JWT", func(t *testing.T) {
		output := captureLogOutput(t)
		token, _, err := oauth2.SignJWT(
			func() (map[string]interface{}, error) {
				return map[string]interface{}{"sub": "user"}, nil
			},
			oauth2.SecretSigner([]byte("test-secret-that-is-long-enough-for-hs256")),
		)
		noErr(t, err)

		LogAccessTokenPayload("access_token", token)

		contains(t, output.String(), "access_token:")
		contains(t, output.String(), `"sub"`)
		contains(t, output.String(), `"user"`)
		notContains(t, output.String(), "(opaque)")
	})

	t.Run("jwe token", func(t *testing.T) {
		output := captureLogOutput(t)
		enc, err := jose.NewEncrypter(
			jose.A256GCM,
			jose.Recipient{
				Algorithm: jose.DIRECT,
				Key:       []byte("0123456789abcdef0123456789abcdef"),
			},
			nil,
		)
		noErr(t, err)

		obj, err := enc.Encrypt([]byte(`{"sub":"user"}`))
		noErr(t, err)
		token, err := obj.CompactSerialize()
		noErr(t, err)

		LogAccessTokenPayload("access_token", token)

		contains(t, output.String(), "access_token: (jwe)")
		notContains(t, output.String(), "(opaque)")
		notContains(t, output.String(), `"sub"`)
	})
}

func TestLogSubjectTokenAndActorTokenWithOpaqueTokens(t *testing.T) {
	output := captureLogOutput(t)

	LogSubjectTokenAndActorToken(oauth2.Request{Form: url.Values{
		"subject_token": {"opaque-subject-token"},
		"actor_token":   {"opaque-actor-token"},
	}})

	contains(t, output.String(), "subject_token: (opaque)")
	contains(t, output.String(), "actor_token: (opaque)")
	notContains(t, output.String(), "ERROR")
	notContains(t, output.String(), "compact JWS")
}

func TestLogInputData(t *testing.T) {
	output := captureLogOutput(t)

	LogInputData(oauth2.ClientConfig{
		IssuerURL:    "https://example.com",
		GrantType:    "authorization_code",
		AuthMethod:   "none",
		Scopes:       []string{"openid", "email"},
		ResponseType: []string{"code"},
		PKCE:         true,
		Nonce:        "n-0S6_WzA2Mj",
		ClientID:     "client",
	})

	got := output.String()
	eq(t, got, strings.Join([]string{
		"issuer_url: https://example.com",
		"grant_type: authorization_code",
		"auth_method: none",
		"scopes: openid, email",
		"response_types: code",
		"pkce: true",
		"nonce: n-0S6_WzA2Mj",
		"client_id: client",
		"",
		"",
	}, "\n"))
}

func TestLogRequest(t *testing.T) {
	output := captureLogOutput(t)
	u, err := url.Parse("https://example.com/authorize?client_id=abc&scope=openid+email")
	noErr(t, err)

	LogRequest(oauth2.Request{
		Method: "GET",
		URL:    u,
	})

	got := output.String()
	contains(t, got, "GET https://example.com/authorize")
	contains(t, got, "  client_id: abc")
	contains(t, got, "  scope: openid email")
	notContains(t, got, "Query params:")
	notContains(t, got, "Headers:")
	notContains(t, got, "Form post:")
}

func TestLogPKCE(t *testing.T) {
	output := captureLogOutput(t)

	LogPKCE("verifier")

	eq(t, output.String(), strings.Join([]string{
		"pkce:",
		"  code_verifier: verifier",
		"  code_challenge: S256(code_verifier)",
		"",
		"",
	}, "\n"))
}

func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()

	output := &bytes.Buffer{}
	prev := logOut
	logOut = output
	t.Cleanup(func() {
		logOut = prev
	})

	return output
}
