package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json/v2"
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

		events := parseTrace(t, output)
		eq(t, len(events), 1)
		eq(t, events[0]["access_token"], "(opaque)")
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

		events := parseTrace(t, output)
		eq(t, len(events), 1)
		claims, ok := events[0]["access_token"].(map[string]any)
		isTrue(t, ok)
		eq(t, claims["sub"], "user")
		eq(t, claims["exp"], float64(1786775334))
		eq(t, claims["iat"], float64(1786739334))
		notContains(t, output.String(), "e+09")
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

		LogToken("access_token", token)

		events := parseTrace(t, output)
		eq(t, len(events), 1)
		eq(t, events[0]["access_token"], "(jwe)")
		notContains(t, output.String(), "(opaque)")
	})
}

func TestLogSubjectTokenAndActorTokenWithOpaqueTokens(t *testing.T) {
	output := captureLogOutput(t)

	LogSubjectTokenAndActorToken(oauth2.Request{Form: url.Values{
		"subject_token": {"opaque-subject-token"},
		"actor_token":   {"opaque-actor-token"},
	}})

	events := parseTrace(t, output)
	eq(t, len(events), 2)
	eq(t, events[0]["subject_token"], "(opaque)")
	eq(t, events[1]["actor_token"], "(opaque)")
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

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	input, ok := events[0]["input"].(map[string]any)
	isTrue(t, ok)
	eq(t, input["issuer_url"], "https://example.com")
	eq(t, input["client_id"], "client")
	eq(t, input["grant_type"], "authorization_code")
	eq(t, input["auth_method"], "none")
	eq(t, input["response_types"], []any{"code"})
	eq(t, input["scopes"], []any{"openid", "email"})
	eq(t, input["resource"], []any{"https://api.example"})
	eq(t, input["pkce"], true)
	eq(t, input["par"], true)
	eq(t, input["nonce"], "n-0S6_WzA2Mj")
}

func TestLogRequest(t *testing.T) {
	output := captureLogOutput(t)
	u, err := url.Parse("https://example.com/authorize?client_id=abc&scope=openid+email")
	noErr(t, err)

	LogRequest(oauth2.Request{
		Method: "GET",
		URL:    u,
	})

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	request, ok := events[0]["request"].(map[string]any)
	isTrue(t, ok)
	eq(t, request["method"], "GET")
	eq(t, request["url"], "https://example.com/authorize")
	eq(t, request["client_id"], "abc")
	eq(t, request["scope"], "openid email")
	_, nested := request["params"]
	eq(t, nested, false)
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
	contains(t, got, `"Authorization":"Basic BASE64(client_id:client_secret)"`)
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

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	request, ok := events[0]["request"].(map[string]any)
	isTrue(t, ok)
	response, ok := request["response"].(map[string]any)
	isTrue(t, ok)
	eq(t, response["token_type"], "Bearer")
	eq(t, response["access_token"], "tok")
	notContains(t, output.String(), "TokenType")
	notContains(t, output.String(), "AccessToken")
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

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	assertion, ok := events[0]["assertion"].(map[string]any)
	isTrue(t, ok)
	eq(t, assertion["encoding"], "JWT-HS256")
	eq(t, assertion["iss"], "client")
	eq(t, assertion["sub"], "client")
	_, nested := assertion["claims"]
	eq(t, nested, false)
}

func TestLogRequestAndResponseNestsResponse(t *testing.T) {
	output := captureLogOutput(t)
	u, err := url.Parse("https://example.com/oauth/token")
	noErr(t, err)

	LogRequestAndResponse(oauth2.Request{
		Method: "POST",
		URL:    u,
		Form:   url.Values{"grant_type": {"client_credentials"}},
	}, map[string]any{"token_type": "Bearer"})

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	request, ok := events[0]["request"].(map[string]any)
	isTrue(t, ok)
	eq(t, request["method"], "POST")
	eq(t, request["url"], "https://example.com/oauth/token")
	eq(t, request["grant_type"], "client_credentials")
	response, ok := request["response"].(map[string]any)
	isTrue(t, ok)
	eq(t, response["token_type"], "Bearer")
	_, topLevel := events[0]["response"]
	eq(t, topLevel, false)
}

func TestLogNonce(t *testing.T) {
	output := captureLogOutput(t)

	LogNonce(oauth2.Request{
		Nonce:       "n-0S6_WzA2Mj",
		NonceSource: oauth2.NonceSourceGenerated,
	})

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	nonce, ok := events[0]["nonce"].(map[string]any)
	isTrue(t, ok)
	eq(t, nonce["spec"], "OpenID Connect Core")
	eq(t, nonce["purpose"], "replay protection")
	eq(t, nonce["source"], "generated")
	eq(t, nonce["value"], "n-0S6_WzA2Mj")
}

func TestLogPKCE(t *testing.T) {
	output := captureLogOutput(t)

	LogPKCE("verifier")

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	pkce, ok := events[0]["pkce"].(map[string]any)
	isTrue(t, ok)
	eq(t, pkce["spec"], "RFC 7636")
	eq(t, pkce["purpose"], "authorization code interception protection")
	eq(t, pkce["code_verifier"], "verifier")
	eq(t, pkce["code_challenge"], "S256(code_verifier)")
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

	events := parseTrace(t, output)
	eq(t, len(events), 8)
	_, ok := events[0]["input"]
	isTrue(t, ok)
	_, ok = events[1]["request"]
	isTrue(t, ok)
	_, ok = events[2]["pkce"]
	isTrue(t, ok)
	eq(t, events[3]["authorization_url"], "https://example.com/authorize?client_id=client")
	eq(t, events[4]["waiting"], "authorization_response")
	request, ok := events[5]["request"].(map[string]any)
	isTrue(t, ok)
	eq(t, request["code"], "abc")
	eq(t, events[6]["access_token"], "(opaque)")
	eq(t, events[7]["id_token"], "(opaque)")
	notContains(t, output.String(), "\n\n")
}

func TestCheckState(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		output := captureLogOutput(t)

		err := CheckState("csrf-state", "csrf-state")
		noErr(t, err)

		check := parseCheck(t, output, "check state")
		eq(t, check["spec"], "RFC 6749")
		eq(t, check["purpose"], "CSRF protection")
		eq(t, check["expected"], "csrf-state")
		eq(t, check["received"], "csrf-state")
		eq(t, check["result"], "pass")
	})

	t.Run("mismatch", func(t *testing.T) {
		output := captureLogOutput(t)

		err := CheckState("csrf-state", "attacker")
		isErr(t, err)
		contains(t, err.Error(), "state does not match")
		eq(t, parseCheck(t, output, "check state")["result"], "fail")
	})
}

func TestCheckIDTokenLogsNonce(t *testing.T) {
	output := captureLogOutput(t)

	err := CheckIDToken("n-0S6_WzA2Mj", oauth2.NonceSourceCustom, "", oauth2.ClientConfig{}, oauth2.ServerConfig{}, nil)
	noErr(t, err)

	check := parseCheck(t, output, "check id_token.nonce")
	eq(t, check["spec"], "OpenID Connect Core")
	eq(t, check["purpose"], "replay protection")
	eq(t, check["source"], "custom")
	eq(t, check["expected"], "n-0S6_WzA2Mj")
	eq(t, check["received"], "(no id_token)")
	eq(t, check["result"], "skip")
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
	contains(t, got, "authorization server did not echo nonce")
	check := parseCheck(t, output, "check id_token.nonce")
	eq(t, check["source"], "generated")
	eq(t, check["received"], "(missing)")
	eq(t, check["result"], "fail")
}

func TestCheckDeviceSlowDown(t *testing.T) {
	output := captureLogOutput(t)

	CheckDeviceSlowDown(oauth2.ErrSlowDown, 10*time.Second)

	check := parseCheck(t, output, "check device.slow_down")
	eq(t, check["spec"], "RFC 8628")
	eq(t, check["received"], "slow_down")
	eq(t, check["detail"], "next interval 10s")
	eq(t, check["result"], "pass")
}

func TestCheckMTLS(t *testing.T) {
	t.Run("omitted alias", func(t *testing.T) {
		output := captureLogOutput(t)
		CheckMTLS(oauth2.Request{
			Cert: &x509.Certificate{},
			URL:  mustParseURL(t, "https://as.example.com/token"),
		})

		check := parseCheck(t, output, "check mtls")
		eq(t, check["spec"], "RFC 8705")
		eq(t, check["received"], "conventional endpoint (no mtls alias advertised): https://as.example.com/token")
		eq(t, check["result"], "pass")
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

	events := parseTrace(t, output)
	eq(t, len(events), 1)
	eq(t, events[0]["error"], "boom")
}

func TestJSONTraceLines(t *testing.T) {
	output := captureLogOutput(t)

	LogInput(oauth2.ClientConfig{
		IssuerURL: "https://example.com",
		ClientID:  "client",
		GrantType: "client_credentials",
	})
	LogRequest(oauth2.Request{
		Method: "POST",
		URL:    mustParseURL(t, "https://example.com/oauth/token"),
		Form:   url.Values{"grant_type": {"client_credentials"}},
	})
	LogWaiting("authorization_response")
	LogURL("authorization_url", "https://example.com/authorize", true)
	LogError(errors.New("boom"))
	_ = CheckState("csrf-state", "csrf-state")

	got := output.String()
	notContains(t, got, "---")
	notContains(t, got, "issuer_url:")

	events := parseTrace(t, output)
	eq(t, len(events), 6)

	input, ok := events[0]["input"].(map[string]any)
	isTrue(t, ok)
	eq(t, input["issuer_url"], "https://example.com")
	eq(t, input["client_id"], "client")

	request, ok := events[1]["request"].(map[string]any)
	isTrue(t, ok)
	eq(t, request["method"], "POST")
	eq(t, request["grant_type"], "client_credentials")
	_, nested := request["params"]
	eq(t, nested, false)

	eq(t, events[2]["waiting"], "authorization_response")
	eq(t, events[3]["authorization_url"], "https://example.com/authorize")
	eq(t, events[4]["error"], "boom")

	check, ok := events[5]["check state"].(map[string]any)
	isTrue(t, ok)
	eq(t, check["result"], "pass")
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

func parseTrace(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var event map[string]any
		noErr(t, json.Unmarshal([]byte(line), &event))
		events = append(events, event)
	}
	return events
}

func parseCheck(t *testing.T, output *bytes.Buffer, name string) map[string]any {
	t.Helper()
	for _, event := range parseTrace(t, output) {
		if check, ok := event[name].(map[string]any); ok {
			return check
		}
	}
	t.Fatalf("missing %q in %s", name, output.String())
	return nil
}
