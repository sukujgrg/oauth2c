package cmd

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cli/browser"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/sukujgrg/oauth2c/internal/oauth2"
)

var logOut io.Writer = os.Stderr

func logln() {
	if silent {
		return
	}

	_, _ = fmt.Fprintln(logOut)
}

func logf(msg string, args ...interface{}) {
	if silent {
		return
	}

	_, _ = fmt.Fprintf(logOut, msg+"\n", args...)
}

func logKV(key, value string) {
	if value == "" {
		return
	}

	logf("%s: %s", key, value)
}

func logBlock(name string, rows [][2]string) {
	if silent {
		return
	}

	logf("%s:", name)
	for _, row := range rows {
		if row[1] == "" {
			continue
		}
		logf("  %s: %s", row[0], row[1])
	}
	endSection()
}

func endSection() {
	logln()
}

func LogWaiting(msg string) {
	logKV("waiting", msg)
	endSection()
}

func LogError(err error) {
	if err == nil {
		return
	}

	_, _ = fmt.Fprintf(logOut, "error: %s\n", err)
}

func LogWarning(msg string) {
	logf("warning: %s", msg)
}

func trueFlag(v bool) string {
	if !v {
		return ""
	}
	return "true"
}

func LogInputData(cc oauth2.ClientConfig) {
	rows := [][2]string{
		{"issuer_url", cc.IssuerURL},
		{"client_id", cc.ClientID},
		{"client_secret", cc.ClientSecret},
		{"grant_type", cc.GrantType},
		{"auth_method", cc.AuthMethod},
		{"response_types", strings.Join(cc.ResponseType, ", ")},
		{"response_mode", cc.ResponseMode},
		{"scopes", strings.Join(cc.Scopes, ", ")},
		{"audience", strings.Join(cc.Audience, ", ")},
		{"acr_values", strings.Join(cc.ACRValues, ", ")},
		{"pkce", trueFlag(cc.PKCE)},
		{"nonce", cc.Nonce},
		{"username", cc.Username},
		{"password", cc.Password},
		{"refresh_token", cc.RefreshToken},
		{"signing_key", cc.SigningKey},
		{"subject_token_type", cc.SubjectTokenType},
		{"actor_token_type", cc.ActorTokenType},
		{"tls_cert", cc.TLSCert},
		{"tls_key", cc.TLSKey},
		{"tls_root_ca", cc.TLSRootCA},
	}

	for _, row := range rows {
		logKV(row[0], row[1])
	}
	endSection()
}

func LogJson(value interface{}) {
	if silent {
		return
	}

	output, err := json.Marshal(value, jsontext.WithIndent("  "))
	if err != nil {
		LogError(err)
		return
	}

	for line := range strings.SplitSeq(strings.TrimRight(string(output), "\n"), "\n") {
		logf("  %s", line)
	}
}

func LogRequest(r oauth2.Request) {
	if silent {
		return
	}

	if r.URL == nil {
		return
	}

	if r.URL.Scheme != "" {
		logf("%s %s://%s%s", r.Method, r.URL.Scheme, r.URL.Host, r.URL.Path)
	} else {
		logf("%s %s", r.Method, r.URL.Path)
	}

	logPairs(r.Headers)
	logPairs(r.URL.Query())
	logPairs(r.Form)

	if r.Cert != nil {
		logf("  certificate_subject: %s", r.Cert.Subject)
		logf("  certificate_issuer: %s", r.Cert.Issuer)
		logf("  certificate_not_before: %s", r.Cert.NotBefore.UTC().Format(time.RFC3339))
		logf("  certificate_not_after: %s", r.Cert.NotAfter.UTC().Format(time.RFC3339))
	}
}

func logPairs(values map[string][]string) {
	if len(values) == 0 {
		return
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, k := range keys {
		logf("  %s: %s", k, strings.Join(values[k], ", "))
	}
}

func LogRequestln(request oauth2.Request) {
	if silent {
		return
	}

	LogRequest(request)
	endSection()
}

func LogRequestAndResponse(request oauth2.Request, response interface{}) {
	if silent {
		return
	}

	LogRequest(request)
	logf("response:")
	LogJson(response)
	endSection()
}

func LogRequestAndResponseln(request oauth2.Request, response interface{}) {
	LogRequestAndResponse(request, response)
}

func LogTokenPayload(response oauth2.TokenResponse) {
	if silent {
		return
	}

	LogAccessTokenPayload("access_token", response.AccessToken)
	LogAccessTokenPayload("id_token", response.IDToken)
}

func LogAccessTokenPayload(label, token string) {
	if silent || token == "" {
		return
	}

	_, claims, err := oauth2.UnsafeParseJWT(token)
	if err == nil {
		logf("%s:", label)
		LogJson(claims)
		endSection()
		return
	}

	if _, encErr := jose.ParseEncrypted(token, oauth2.JOSEKeyAlgorithms, oauth2.JOSEContentEncryption); encErr == nil {
		logKV(label, "(jwe)")
		endSection()
		return
	}

	logKV(label, "(opaque)")
	endSection()
}

func LogTokenPayloadln(response oauth2.TokenResponse) {
	LogTokenPayload(response)
}

func LogPKCE(codeVerifier string) {
	if codeVerifier == "" {
		return
	}

	logBlock("pkce", [][2]string{
		{"code_verifier", codeVerifier},
		{"code_challenge", "S256(code_verifier)"},
	})
}

func CheckNonce(expected, idToken string, clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	if expected == "" || idToken == "" {
		return nil
	}

	got, err := oauth2.CheckIDTokenNonce(idToken, expected, serverConfig, clientConfig, hc)

	if !silent {
		received := got
		switch {
		case errors.Is(err, oauth2.ErrIDTokenNonceMissing):
			received = "(missing)"
		case err != nil && got == "":
			received = "(unverified)"
		}

		logBlock("nonce", [][2]string{
			{"sent", expected},
			{"id_token", received},
			{"match", strconv.FormatBool(err == nil)},
		})
	}

	return err
}

func LogAuthMethod(config oauth2.ClientConfig) {
	if config.AuthMethod != oauth2.ClientSecretBasicAuthMethod {
		return
	}

	logBlock("auth", [][2]string{
		{"authorization", "Basic BASE64(client_id:client_secret)"},
	})
}

func LogJARM(request oauth2.Request) {
	if silent || len(request.JARM) == 0 {
		return
	}

	logf("jarm:")
	LogJson(request.JARM)
	endSection()
}

func LogRequestObject(r oauth2.Request) {
	var (
		request        = r.URL.Query().Get("request")
		requestClaims  map[string]interface{}
		token          *jwt.JSONWebToken
		encryptedToken *jose.JSONWebEncryption
		err            error
	)

	if request == "" {
		request = r.Form.Get("request")
	}

	if silent || request == "" {
		return
	}

	if token, requestClaims, err = oauth2.UnsafeParseJWT(r.RequestObject); err != nil {
		LogError(err)
		return
	}

	if encryptedToken, err = jose.ParseEncrypted(request, oauth2.JOSEKeyAlgorithms, oauth2.JOSEContentEncryption); err == nil {
		logKV("request_object", fmt.Sprintf("JWE-%s(JWT-%s)", encryptedToken.Header.Algorithm, token.Headers[0].Algorithm))
	} else {
		logKV("request_object", fmt.Sprintf("JWT-%s", token.Headers[0].Algorithm))
	}

	LogJson(requestClaims)
	endSection()
}

func LogAssertion(request oauth2.Request, name string) {
	var (
		assertion = request.Form.Get(name)
		token     *jwt.JSONWebToken
		claims    map[string]interface{}
		err       error
	)

	if silent || assertion == "" {
		return
	}

	if token, claims, err = oauth2.UnsafeParseJWT(assertion); err != nil {
		LogError(err)
		return
	}

	logKV(name, fmt.Sprintf("JWT-%s", token.Headers[0].Algorithm))
	LogJson(claims)
	endSection()
}

func LogSubjectTokenAndActorToken(request oauth2.Request) {
	if silent {
		return
	}

	LogAccessTokenPayload("subject_token", request.Form.Get("subject_token"))
	LogAccessTokenPayload("actor_token", request.Form.Get("actor_token"))
}

func LogAuthURL(url string, noBrowser bool) {
	if noBrowser && silent {
		_, _ = fmt.Fprintln(os.Stderr, url)
		return
	}

	logKV("url", url)
	endSection()

	if !noBrowser {
		if err := browser.OpenURL(url); err != nil {
			LogError(err)
		}
	}
}
