package cmd

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cli/browser"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

var logOut io.Writer = os.Stderr

func logln() {
	if silent {
		return
	}

	fmt.Fprintln(logOut)
}

func logf(msg string, args ...interface{}) {
	if silent {
		return
	}

	fmt.Fprintf(logOut, msg+"\n", args...)
}

func Logln() {
	logln()
}

func Logfln(msg string, args ...interface{}) {
	logf(msg, args...)
}

func LogHeader(msg string) {
	logf("%s", msg)
}

func LogSection(msg string) {
	logf("%s", msg)
}

func LogAction(msg string) func(string) {
	if silent {
		return func(string) {}
	}

	logf("%s", msg)
	return func(s string) {
		logf("%s", s)
		logln()
	}
}

func LogBox(title string, msg string, args ...interface{}) {
	if silent {
		return
	}

	logf("%s", title)
	logf(msg, args...)
}

func LogError(err error) {
	if err == nil {
		return
	}

	fmt.Fprintf(logOut, "Error: %s\n", err)
}

func LogWarning(msg string) {
	logf("Warning: %s", msg)
}

func LogInputData(cc oauth2.ClientConfig) {
	if silent {
		return
	}

	rows := [][2]string{
		{"Issuer URL", cc.IssuerURL},
		{"Grant type", cc.GrantType},
		{"Auth method", cc.AuthMethod},
		{"Scopes", strings.Join(cc.Scopes, ", ")},
		{"ACR Values", strings.Join(cc.ACRValues, ", ")},
		{"Audience", strings.Join(cc.Audience, ", ")},
		{"Response types", strings.Join(cc.ResponseType, ", ")},
		{"Response mode", cc.ResponseMode},
		{"PKCE", strconv.FormatBool(cc.PKCE)},
		{"Nonce", cc.Nonce},
		{"Client ID", cc.ClientID},
		{"Client secret", cc.ClientSecret},
		{"Username", cc.Username},
		{"Password", cc.Password},
		{"Refresh token", cc.RefreshToken},
		{"Signing key", cc.SigningKey},
		{"Subject token type", cc.SubjectTokenType},
		{"Actors token type", cc.ActorTokenType},
		{"TLS client cert", cc.TLSCert},
		{"TLS client key", cc.TLSKey},
		{"TLS root CA", cc.TLSRootCA},
	}

	for _, row := range rows {
		if row[1] == "" {
			continue
		}

		logf("%-22s %s", row[0], row[1])
	}

	logln()
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

	fmt.Fprintln(logOut, string(output))
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

	if len(r.Headers) > 0 {
		logf("Headers:")
	}

	for k, vs := range r.Headers {
		logf("  %s: %s", k, strings.Join(vs, ", "))
	}

	if len(r.URL.Query()) > 0 {
		logf("Query params:")
	}

	for k, vs := range r.URL.Query() {
		logf("  %s: %s", k, strings.Join(vs, ", "))
	}

	if len(r.Form) > 0 {
		logf("Form post:")
	}

	for k, vs := range r.Form {
		logf("  %s: %s", k, strings.Join(vs, ", "))
	}

	if r.Cert != nil {
		logln()
		logf("Certificate:")
		logf("  Subject: %s", r.Cert.Subject)
		logf("  Issuer: %s", r.Cert.Issuer)
		logf("  NotBefore: %s", r.Cert.NotBefore.UTC().Format(time.RFC3339))
		logf("  NotAfter: %s", r.Cert.NotAfter.UTC().Format(time.RFC3339))
	}
}

func LogRequestln(request oauth2.Request) {
	if silent {
		return
	}

	LogRequest(request)
	logln()
}

func LogRequestAndResponse(request oauth2.Request, response interface{}) {
	if silent {
		return
	}

	LogRequest(request)
	logf("Response:")
	LogJson(response)
}

func LogRequestAndResponseln(request oauth2.Request, response interface{}) {
	if silent {
		return
	}

	LogRequestAndResponse(request, response)
	logln()
}

func LogTokenPayload(response oauth2.TokenResponse) {
	var (
		idClaims map[string]interface{}
		err      error
	)

	if silent {
		return
	}

	LogAccessTokenPayload("Access token", response.AccessToken)

	if response.IDToken != "" {
		if _, idClaims, err = oauth2.UnsafeParseJWT(response.IDToken); err != nil {
			LogError(err)
		} else {
			logf("ID token:")
			LogJson(idClaims)
		}
	}
}

func LogAccessTokenPayload(label, token string) {
	if silent || token == "" {
		return
	}

	_, claims, err := oauth2.UnsafeParseJWT(token)
	if err != nil {
		logf("%s: (opaque or non-JWT)", label)
		return
	}

	logf("%s:", label)
	LogJson(claims)
}

func LogTokenPayloadln(response oauth2.TokenResponse) {
	if silent {
		return
	}

	LogTokenPayload(response)
	logln()
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

		LogBox("Nonce", "nonce = %s\nID Token nonce = %s\nmatch = %t", expected, received, err == nil)
		logln()
	}

	return err
}

func LogAuthMethod(config oauth2.ClientConfig) {
	if silent {
		return
	}

	switch config.AuthMethod {
	case oauth2.ClientSecretBasicAuthMethod:
		LogBox("Client Secret Basic", "Authorization = Basic BASE64-ENCODE(ClientID:ClientSecret)")
		logln()
	}
}

func LogJARM(request oauth2.Request) {
	if silent {
		return
	}

	if len(request.JARM) != 0 {
		logf("JARM:")
		LogJson(request.JARM)
	}
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

	if silent {
		return
	}

	if request != "" {
		if token, requestClaims, err = oauth2.UnsafeParseJWT(r.RequestObject); err != nil {
			LogError(err)
		} else {
			if encryptedToken, err = jose.ParseEncrypted(request, oauth2.JOSEKeyAlgorithms, oauth2.JOSEContentEncryption); err == nil {
				LogBox("Request object", "request = JWE-%s(JWT-%s(payload))", encryptedToken.Header.Algorithm, token.Headers[0].Algorithm)
			} else {
				LogBox("Request object", "request = JWT-%s(payload)", token.Headers[0].Algorithm)
			}

			logln()
			logf("Payload")
			LogJson(requestClaims)
			logln()
		}
	}
}

func LogAssertion(request oauth2.Request, title string, name string) {
	var (
		assertion = request.Form.Get(name)
		token     *jwt.JSONWebToken
		claims    map[string]interface{}
		err       error
	)

	if silent {
		return
	}

	if assertion == "" {
		return
	}

	if token, claims, err = oauth2.UnsafeParseJWT(assertion); err != nil {
		LogError(err)
		return
	}

	LogBox(title, "%s = JWT-%s(payload)", name, token.Headers[0].Algorithm)
	logln()
	logf("Payload")
	LogJson(claims)
	logln()
}

func LogSubjectTokenAndActorToken(request oauth2.Request) {
	var (
		subjectToken = request.Form.Get("subject_token")
		actorToken   = request.Form.Get("actor_token")
	)

	if silent {
		return
	}

	LogAccessTokenPayload("Subject token", subjectToken)
	LogAccessTokenPayload("Actor token", actorToken)

	if subjectToken != "" || actorToken != "" {
		logln()
	}
}

func LogAuthURL(url string, noBrowser bool) {
	if noBrowser && silent {
		fmt.Fprintln(os.Stderr, url)
	} else {
		Logfln("\nGo to the following URL:\n\n%s", url)
	}

	if !noBrowser {
		Logfln("\nOpening browser...")
		if err := browser.OpenURL(url); err != nil {
			LogError(err)
		}
	}
}
