package cmd

import (
	"bytes"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sukujgrg/oauth2c/internal/oauth2"
)

func TestLogToken(t *testing.T) {
	t.Run("opaque token", func(t *testing.T) {
		output := captureLogOutput(t)

		LogTokens(oauth2.TokenResponse{AccessToken: "opaque-access-token"})

		contains(t, output.String(), "access_token: (opaque)")
		notContains(t, output.String(), "ERROR")
		notContains(t, output.String(), "compact JWS")
	})

	t.Run("signed JWT", func(t *testing.T) {
		output := captureLogOutput(t)
		token, _, err := oauth2.SignJWT(
			func() (map[string]interface{}, error) {
				return map[string]interface{}{
					"sub": "user",
					"exp": int64(1786775334),
					"iat": int64(1786739334),
				}, nil
			},
			oauth2.SecretSigner([]byte("test-secret-that-is-long-enough-for-hs256")),
		)
		noErr(t, err)

		LogToken("access_token", token)

		contains(t, output.String(), "access_token:")
		contains(t, output.String(), "  sub: user")
		contains(t, output.String(), "  exp: 1786775334")
		contains(t, output.String(), "  iat: 1786739334")
		notContains(t, output.String(), "e+09")
		notContains(t, output.String(), "(opaque)")
		notContains(t, output.String(), "{")
		notContains(t, output.String(), `"sub"`)
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

		LogToken("access_token", token)

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

func TestLogInput(t *testing.T) {
	output := captureLogOutput(t)

	LogInput(oauth2.ClientConfig{
		IssuerURL:    "https://example.com",
		GrantType:    "authorization_code",
		AuthMethod:   "none",
		Scopes:       []string{"openid", "email"},
		ResponseType: []string{"code"},
		Resource:     []string{"https://api.example"},
		PKCE:         true,
		PAR:          true,
		Nonce:        "n-0S6_WzA2Mj",
		ClientID:     "client",
	})

	got := output.String()
	eq(t, got, strings.Join([]string{
		"input:",
		"  issuer_url: https://example.com",
		"  client_id: client",
		"  grant_type: authorization_code",
		"  auth_method: none",
		"  response_types: [code]",
		"  scopes: [openid, email]",
		"  resource: ['https://api.example']",
		"  pkce: true",
		"  par: true",
		"  nonce: n-0S6_WzA2Mj",
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
	contains(t, got, "request:")
	contains(t, got, "  method: GET")
	contains(t, got, "  url: https://example.com/authorize")
	contains(t, got, "  client_id: abc")
	contains(t, got, "  scope: openid email")
	notContains(t, got, "Query params:")
	notContains(t, got, "Headers:")
	notContains(t, got, "Form post:")
}

func TestLogRequestRedactsBasicAuth(t *testing.T) {
	output := captureLogOutput(t)
	u, err := url.Parse("https://example.com/oauth/token")
	noErr(t, err)

	LogRequest(oauth2.Request{
		Method: "POST",
		URL:    u,
		Headers: http.Header{
			"Authorization": []string{"Basic dXNlcjpwYXNz"},
		},
		Form: url.Values{"grant_type": {"client_credentials"}},
	})

	got := output.String()
	contains(t, got, "Authorization: Basic BASE64(client_id:client_secret)")
	notContains(t, got, "dXNlcjpwYXNz")
}

func TestLogRequestAndResponseUsesJSONFieldNames(t *testing.T) {
	output := captureLogOutput(t)
	u, err := url.Parse("https://example.com/oauth/token")
	noErr(t, err)

	LogRequestAndResponse(oauth2.Request{
		Method: "POST",
		URL:    u,
	}, oauth2.TokenResponse{TokenType: "Bearer", AccessToken: "tok"})

	got := output.String()
	contains(t, got, "  response:")
	contains(t, got, "    token_type: Bearer")
	contains(t, got, "    access_token: tok")
	notContains(t, got, "TokenType")
	notContains(t, got, "AccessToken")
}

func TestLogAssertion(t *testing.T) {
	output := captureLogOutput(t)
	token, _, err := oauth2.SignJWT(
		func() (map[string]interface{}, error) {
			return map[string]interface{}{"iss": "client", "sub": "client"}, nil
		},
		oauth2.SecretSigner([]byte("test-secret-that-is-long-enough-for-hs256")),
	)
	noErr(t, err)

	LogAssertion(oauth2.Request{Form: url.Values{"assertion": {token}}}, "assertion")

	got := output.String()
	contains(t, got, "assertion:")
	contains(t, got, "  encoding: JWT-HS256")
	contains(t, got, "  iss: client")
	contains(t, got, "  sub: client")
	notContains(t, got, "assertion: JWT")
}

func TestLogRequestAndResponseIndentsResponse(t *testing.T) {
	output := captureLogOutput(t)
	u, err := url.Parse("https://example.com/oauth/token")
	noErr(t, err)

	LogRequestAndResponse(oauth2.Request{
		Method: "POST",
		URL:    u,
		Form:   url.Values{"grant_type": {"client_credentials"}},
	}, map[string]any{"token_type": "Bearer"})

	got := output.String()
	contains(t, got, "request:")
	contains(t, got, "  method: POST")
	contains(t, got, "  url: https://example.com/oauth/token")
	contains(t, got, "  grant_type: client_credentials")
	contains(t, got, "  response:")
	contains(t, got, "    token_type: Bearer")
	notContains(t, got, "\nresponse:")
	notContains(t, got, "{")
	notContains(t, got, `"token_type"`)
}

func TestLogNonce(t *testing.T) {
	output := captureLogOutput(t)

	LogNonce(oauth2.Request{
		Nonce:       "n-0S6_WzA2Mj",
		NonceSource: oauth2.NonceSourceGenerated,
	})

	eq(t, output.String(), strings.Join([]string{
		"nonce:",
		"  spec: OpenID Connect Core",
		"  purpose: replay protection",
		"  source: generated",
		"  value: n-0S6_WzA2Mj",
		"",
		"",
	}, "\n"))
}

func TestLogPKCE(t *testing.T) {
	output := captureLogOutput(t)

	LogPKCE("verifier")

	eq(t, output.String(), strings.Join([]string{
		"pkce:",
		"  spec: RFC 7636",
		"  purpose: authorization code interception protection",
		"  code_verifier: verifier",
		"  code_challenge: S256(code_verifier)",
		"",
		"",
	}, "\n"))
}

func TestLogSectionSpacing(t *testing.T) {
	output := captureLogOutput(t)

	LogInput(oauth2.ClientConfig{
		IssuerURL: "https://example.com",
		GrantType: "authorization_code",
		ClientID:  "client",
	})
	LogRequest(oauth2.Request{
		Method: "GET",
		URL:    mustParseURL(t, "https://example.com/authorize?client_id=client"),
	})
	LogPKCE("verifier")
	LogURL("authorization_url", "https://example.com/authorize?client_id=client", true)
	LogWaiting("authorization_response")
	LogRequest(oauth2.Request{
		Method: "GET",
		URL:    mustParseURL(t, "/callback?code=abc"),
	})
	LogTokens(oauth2.TokenResponse{
		AccessToken: "opaque-access-token",
		IDToken:     "opaque-id-token",
	})

	got := output.String()
	eq(t, got, strings.Join([]string{
		"input:",
		"  issuer_url: https://example.com",
		"  client_id: client",
		"  grant_type: authorization_code",
		"",
		"request:",
		"  method: GET",
		"  url: https://example.com/authorize",
		"  client_id: client",
		"",
		"pkce:",
		"  spec: RFC 7636",
		"  purpose: authorization code interception protection",
		"  code_verifier: verifier",
		"  code_challenge: S256(code_verifier)",
		"",
		"authorization_url: https://example.com/authorize?client_id=client",
		"",
		"waiting: authorization_response",
		"",
		"request:",
		"  method: GET",
		"  url: /callback",
		"  code: abc",
		"",
		"access_token: (opaque)",
		"",
		"id_token: (opaque)",
		"",
		"",
	}, "\n"))
	notContains(t, got, "\n\n\n")
}

func TestCheckState(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		output := captureLogOutput(t)

		err := CheckState("csrf-state", "csrf-state")
		noErr(t, err)

		got := output.String()
		contains(t, got, "check state:")
		contains(t, got, "  spec: RFC 6749")
		contains(t, got, "  purpose: CSRF protection")
		contains(t, got, "  expected: csrf-state")
		contains(t, got, "  received: csrf-state")
		contains(t, got, "  result: pass")
	})

	t.Run("mismatch", func(t *testing.T) {
		output := captureLogOutput(t)

		err := CheckState("csrf-state", "attacker")
		isErr(t, err)
		contains(t, err.Error(), "state does not match")
		contains(t, output.String(), "  result: fail")
	})
}

func TestCheckIDTokenLogsNonce(t *testing.T) {
	output := captureLogOutput(t)

	err := CheckIDToken("n-0S6_WzA2Mj", oauth2.NonceSourceCustom, "", oauth2.ClientConfig{}, oauth2.ServerConfig{}, nil)
	noErr(t, err)

	got := output.String()
	contains(t, got, "check id_token.nonce:")
	contains(t, got, "  spec: OpenID Connect Core")
	contains(t, got, "  purpose: replay protection")
	contains(t, got, "  source: custom")
	contains(t, got, "  expected: n-0S6_WzA2Mj")
	contains(t, got, "  received: (no id_token)")
	contains(t, got, "  result: skip")
}

func TestCheckIDTokenMissingNonceContinues(t *testing.T) {
	output := captureLogOutput(t)
	secret := "test-secret-that-is-long-enough-for-hs256"
	now := time.Now()
	token, _, err := oauth2.SignJWT(func() (map[string]interface{}, error) {
		return map[string]interface{}{
			"iss": "https://example.com",
			"aud": "client",
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
		}, nil
	}, oauth2.SecretSigner([]byte(secret)))
	noErr(t, err)

	err = CheckIDToken("dbd27db6-b0bc-4945-9a61-0b40c304d1d9", oauth2.NonceSourceGenerated, token, oauth2.ClientConfig{
		IssuerURL:    "https://example.com",
		ClientID:     "client",
		ClientSecret: secret,
	}, oauth2.ServerConfig{Issuer: "https://example.com"}, http.DefaultClient)
	noErr(t, err)

	got := output.String()
	contains(t, got, "check id_token.nonce:")
	contains(t, got, "  source: generated")
	contains(t, got, "  received: (missing)")
	contains(t, got, "  result: fail")
	contains(t, got, "authorization server did not echo nonce")
}

func TestCheckDeviceSlowDown(t *testing.T) {
	output := captureLogOutput(t)

	CheckDeviceSlowDown(oauth2.ErrSlowDown, 10*time.Second)

	got := output.String()
	contains(t, got, "check device.slow_down:")
	contains(t, got, "  spec: RFC 8628")
	contains(t, got, "  received: slow_down")
	contains(t, got, "  detail: next interval 10s")
	contains(t, got, "  result: pass")
}

func TestCheckMTLS(t *testing.T) {
	t.Run("omitted alias", func(t *testing.T) {
		output := captureLogOutput(t)
		CheckMTLS(oauth2.Request{
			Cert: &x509.Certificate{},
			URL:  mustParseURL(t, "https://as.example.com/token"),
		})

		got := output.String()
		contains(t, got, "check mtls:")
		contains(t, got, "  spec: RFC 8705")
		contains(t, got, "conventional endpoint (no mtls alias advertised): https://as.example.com/token")
		contains(t, got, "  result: pass")
	})

	t.Run("no certificate is silent", func(t *testing.T) {
		output := captureLogOutput(t)
		CheckMTLS(oauth2.Request{})
		eq(t, output.String(), "")
	})
}

func TestSilentDiscardsTrace(t *testing.T) {
	output := captureLogOutput(t)
	prev := silent
	silent = true
	t.Cleanup(func() { silent = prev })

	LogInput(oauth2.ClientConfig{IssuerURL: "https://example.com", ClientID: "client"})
	LogError(errors.New("boom"))
	LogWarning("pkce required")
	LogPKCE("verifier")
	LogWaiting("authorization_response")
	LogURL("authorization_url", "https://example.com/authorize", true)
	LogRequest(oauth2.Request{
		Method: "GET",
		URL:    mustParseURL(t, "https://example.com/authorize?client_id=client"),
	})
	LogRequestAndResponse(oauth2.Request{
		Method: "POST",
		URL:    mustParseURL(t, "https://example.com/oauth/token"),
		Form:   url.Values{"grant_type": {"client_credentials"}},
	}, map[string]any{"token_type": "Bearer"})
	LogTokens(oauth2.TokenResponse{AccessToken: "opaque-access-token"})
	_ = CheckState("csrf-state", "csrf-state")

	eq(t, output.String(), "")
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	noErr(t, err)
	return u
}

func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()

	output := &bytes.Buffer{}
	prev := trace.w
	trace.w = output
	t.Cleanup(func() {
		trace.w = prev
	})

	return output
}
