package cmd

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cli/browser"
	"github.com/go-jose/go-jose/v4"

	"github.com/sukujgrg/oauth2c/internal/oauth2"
	"github.com/sukujgrg/oauth2c/internal/yamlprint"
)

// trace is the educational stderr log. --silent discards it so only the
// token JSON on stdout remains.
var trace = stderrLog{w: os.Stderr}

type stderrLog struct {
	w io.Writer
}

func (l *stderrLog) enabled() bool {
	return !silent && l != nil && l.w != nil && l.w != io.Discard
}

func (l *stderrLog) writer() io.Writer {
	if !l.enabled() {
		return io.Discard
	}
	return l.w
}

func (l *stderrLog) line(format string, args ...any) {
	if !l.enabled() {
		return
	}
	_, _ = fmt.Fprintf(l.writer(), format+"\n", args...)
}

func (l *stderrLog) yaml(v any) {
	if !l.enabled() {
		return
	}
	if err := yml.Write(l.writer(), v); err != nil {
		l.error(err)
	}
}

func (l *stderrLog) doc(v any) {
	l.yaml(v)
	l.line("")
}

func (l *stderrLog) error(err error) {
	if err == nil || !l.enabled() {
		return
	}
	if writeErr := yml.Write(l.writer(), struct {
		Error string `yaml:"error"`
	}{Error: err.Error()}); writeErr != nil {
		_, _ = fmt.Fprintf(l.writer(), "error: %s\n", err)
	}
}

var yml = yamlprint.New()

func printSection(name string, v any) {
	if name == "" {
		return
	}
	trace.doc(map[string]any{name: v})
}

func LogWaiting(msg string) {
	printSection("waiting", msg)
}

func LogError(err error) {
	trace.error(err)
}

func LogWarning(msg string) {
	printSection("warning", msg)
}

func LogInput(cc oauth2.ClientConfig) {
	printSection("input", clientInputLog{
		IssuerURL:              cc.IssuerURL,
		ClientID:               cc.ClientID,
		ClientSecret:           cc.ClientSecret,
		GrantType:              cc.GrantType,
		AuthMethod:             cc.AuthMethod,
		ResponseTypes:          compactStrings(cc.ResponseType),
		ResponseMode:           cc.ResponseMode,
		RedirectURL:            cc.RedirectURL,
		Scopes:                 compactStrings(cc.Scopes),
		Audience:               compactStrings(cc.Audience),
		Resource:               compactStrings(cc.Resource),
		ACRValues:              compactStrings(cc.ACRValues),
		PKCE:                   cc.PKCE,
		PAR:                    cc.PAR,
		RequestObject:          cc.RequestObject,
		EncryptedRequestObject: cc.EncryptedRequestObject,
		DPoP:                   cc.DPoP,
		Nonce:                  cc.Nonce,
		Username:               cc.Username,
		Password:               cc.Password,
		RefreshToken:           cc.RefreshToken,
		SigningKey:             cc.SigningKey,
		SubjectTokenType:       cc.SubjectTokenType,
		ActorTokenType:         cc.ActorTokenType,
		IDTokenHint:            cc.IDTokenHint,
		LoginHint:              cc.LoginHint,
		IDPHint:                cc.IDPHint,
		Claims:                 cc.Claims,
		RAR:                    cc.RAR,
		Prompt:                 compactStrings(cc.Prompt),
		MaxAge:                 cc.MaxAge,
		Purpose:                cc.Purpose,
		AuthenticationCode:     cc.AuthenticationCode,
		TLSCert:                cc.TLSCert,
		TLSKey:                 cc.TLSKey,
		TLSRootCA:              cc.TLSRootCA,
	})
}

func LogRequest(r oauth2.Request) {
	if r.URL == nil {
		return
	}
	printSection("request", requestFields(r, nil))
}

func LogRequestAndResponse(request oauth2.Request, response interface{}) {
	var generic any
	if response != nil {
		var err error
		generic, err = yamlprint.FromJSON(response)
		if err != nil {
			LogError(err)
			return
		}
	}

	if request.URL == nil {
		if generic != nil {
			printSection("response", generic)
		}
		return
	}

	printSection("request", requestFields(request, generic))
}

func LogTokens(response oauth2.TokenResponse) {
	LogToken("access_token", response.AccessToken)
	LogToken("id_token", response.IDToken)
}

func LogToken(label, token string) {
	if !trace.enabled() || token == "" {
		return
	}

	_, claims, err := oauth2.UnsafeParseJWT(token)
	if err == nil {
		printSection(label, claims)
		return
	}

	if _, encErr := jose.ParseEncrypted(token, oauth2.JOSEKeyAlgorithms, oauth2.JOSEContentEncryption); encErr == nil {
		printSection(label, "(jwe)")
		return
	}

	printSection(label, "(opaque)")
}

func nonceSent(reqs ...oauth2.Request) (value, source string) {
	for _, r := range reqs {
		if r.Nonce != "" {
			return r.Nonce, r.NonceSource
		}
	}
	return "", ""
}

func LogNonce(r oauth2.Request) {
	if r.Nonce == "" {
		return
	}

	printSection("nonce", nonceLog{
		Spec:    "OpenID Connect Core",
		Purpose: "replay protection",
		Source:  r.NonceSource,
		Value:   r.Nonce,
	})
}

func LogPKCE(codeVerifier string) {
	if codeVerifier == "" {
		return
	}

	printSection("pkce", pkceLog{
		Spec:          "RFC 7636",
		Purpose:       "authorization code interception protection",
		CodeVerifier:  codeVerifier,
		CodeChallenge: "S256(code_verifier)",
	})
}

func LogVerification(v oauth2.Verification) {
	if v.Name == "" {
		return
	}
	printSection("check "+v.Name, v)
}

func LogVerifications(checks []oauth2.Verification) {
	for _, check := range checks {
		LogVerification(check)
	}
}

func CheckState(expected, received string) error {
	result := oauth2.CheckPass
	var err error
	if expected == "" {
		result = oauth2.CheckFail
		err = errors.New("missing expected state")
	} else if subtle.ConstantTimeCompare([]byte(expected), []byte(received)) != 1 {
		result = oauth2.CheckFail
		err = errors.New("state does not match")
	}

	LogVerification(oauth2.Verification{
		Name:     "state",
		Spec:     "RFC 6749",
		Purpose:  "CSRF protection",
		Expected: expected,
		Received: received,
		Result:   result,
	})

	return err
}

func CheckIDToken(expectedNonce, nonceSource, idToken string, clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	if idToken == "" && expectedNonce == "" {
		return nil
	}

	_, checks, err := oauth2.VerifyIDTokenWithNonce(idToken, expectedNonce, serverConfig, clientConfig, hc)
	if nonceSource != "" {
		for i := range checks {
			if checks[i].Name == "id_token.nonce" {
				checks[i].Source = nonceSource
			}
		}
	}
	LogVerifications(checks)
	if errors.Is(err, oauth2.ErrIDTokenNonceMissing) {
		return nil
	}
	return err
}

func CheckMTLS(request oauth2.Request) {
	if request.Cert == nil {
		return
	}

	received := "conventional endpoint (no mtls alias advertised)"
	if request.UsedMTLSAlias {
		received = "mtls_endpoint_aliases"
	}
	if request.URL != nil {
		received += ": " + request.URL.String()
	}

	LogVerification(oauth2.Verification{
		Name:     "mtls",
		Spec:     "RFC 8705",
		Purpose:  "certificate-bound client authentication",
		Received: received,
		Result:   oauth2.CheckPass,
	})
}

func CheckDeviceSlowDown(errorCode string, interval time.Duration) {
	LogVerification(oauth2.Verification{
		Name:     "device.slow_down",
		Spec:     "RFC 8628",
		Purpose:  "increase polling interval by 5s",
		Received: errorCode,
		Detail:   "next interval " + interval.String(),
		Result:   oauth2.CheckPass,
	})
}

func LogJARM(request oauth2.Request) {
	if len(request.JARM) == 0 {
		return
	}
	printSection("jarm", request.JARM)
}

func LogRequestObject(r oauth2.Request) {
	if !trace.enabled() {
		return
	}

	var request string
	if r.URL != nil {
		request = r.URL.Query().Get("request")
	}
	if request == "" {
		request = r.Form.Get("request")
	}
	if request == "" {
		return
	}

	token, requestClaims, err := oauth2.UnsafeParseJWT(r.RequestObject)
	if err != nil {
		LogError(err)
		return
	}

	encoding := fmt.Sprintf("JWT-%s", token.Headers[0].Algorithm)
	if encryptedToken, encErr := jose.ParseEncrypted(request, oauth2.JOSEKeyAlgorithms, oauth2.JOSEContentEncryption); encErr == nil {
		encoding = fmt.Sprintf("JWE-%s(JWT-%s)", encryptedToken.Header.Algorithm, token.Headers[0].Algorithm)
	}

	printSection("request_object", signedJWTLog{
		Encoding: encoding,
		Claims:   requestClaims,
	})
}

func LogAssertion(request oauth2.Request, name string) {
	if !trace.enabled() {
		return
	}

	assertion := request.Form.Get(name)
	if assertion == "" {
		return
	}

	token, claims, err := oauth2.UnsafeParseJWT(assertion)
	if err != nil {
		LogError(err)
		return
	}

	printSection(name, signedJWTLog{
		Encoding: fmt.Sprintf("JWT-%s", token.Headers[0].Algorithm),
		Claims:   claims,
	})
}

func LogSubjectTokenAndActorToken(request oauth2.Request) {
	LogToken("subject_token", request.Form.Get("subject_token"))
	LogToken("actor_token", request.Form.Get("actor_token"))
}

func LogURL(name, rawURL string, noBrowser bool) {
	printSection(name, rawURL)

	if !noBrowser {
		if err := browser.OpenURL(rawURL); err != nil {
			LogError(err)
		}
	}
}

type clientInputLog struct {
	IssuerURL              string   `yaml:"issuer_url,omitempty"`
	ClientID               string   `yaml:"client_id,omitempty"`
	ClientSecret           string   `yaml:"client_secret,omitempty"`
	GrantType              string   `yaml:"grant_type,omitempty"`
	AuthMethod             string   `yaml:"auth_method,omitempty"`
	ResponseTypes          []string `yaml:"response_types,omitempty,flow"`
	ResponseMode           string   `yaml:"response_mode,omitempty"`
	RedirectURL            string   `yaml:"redirect_url,omitempty"`
	Scopes                 []string `yaml:"scopes,omitempty,flow"`
	Audience               []string `yaml:"audience,omitempty,flow"`
	Resource               []string `yaml:"resource,omitempty,flow"`
	ACRValues              []string `yaml:"acr_values,omitempty,flow"`
	PKCE                   bool     `yaml:"pkce,omitempty"`
	PAR                    bool     `yaml:"par,omitempty"`
	RequestObject          bool     `yaml:"request_object,omitempty"`
	EncryptedRequestObject bool     `yaml:"encrypted_request_object,omitempty"`
	DPoP                   bool     `yaml:"dpop,omitempty"`
	Nonce                  string   `yaml:"nonce,omitempty"`
	Username               string   `yaml:"username,omitempty"`
	Password               string   `yaml:"password,omitempty"`
	RefreshToken           string   `yaml:"refresh_token,omitempty"`
	SigningKey             string   `yaml:"signing_key,omitempty"`
	SubjectTokenType       string   `yaml:"subject_token_type,omitempty"`
	ActorTokenType         string   `yaml:"actor_token_type,omitempty"`
	IDTokenHint            string   `yaml:"id_token_hint,omitempty"`
	LoginHint              string   `yaml:"login_hint,omitempty"`
	IDPHint                string   `yaml:"idp_hint,omitempty"`
	Claims                 string   `yaml:"claims,omitempty"`
	RAR                    string   `yaml:"rar,omitempty"`
	Prompt                 []string `yaml:"prompt,omitempty,flow"`
	MaxAge                 string   `yaml:"max_age,omitempty"`
	Purpose                string   `yaml:"purpose,omitempty"`
	AuthenticationCode     string   `yaml:"authentication_code,omitempty"`
	TLSCert                string   `yaml:"tls_cert,omitempty"`
	TLSKey                 string   `yaml:"tls_key,omitempty"`
	TLSRootCA              string   `yaml:"tls_root_ca,omitempty"`
}

type nonceLog struct {
	Spec    string `yaml:"spec,omitempty"`
	Purpose string `yaml:"purpose,omitempty"`
	Source  string `yaml:"source,omitempty"`
	Value   string `yaml:"value,omitempty"`
}

type pkceLog struct {
	Spec          string `yaml:"spec,omitempty"`
	Purpose       string `yaml:"purpose,omitempty"`
	CodeVerifier  string `yaml:"code_verifier,omitempty"`
	CodeChallenge string `yaml:"code_challenge,omitempty"`
}

type signedJWTLog struct {
	Encoding string         `yaml:"encoding"`
	Claims   map[string]any `yaml:",inline"`
}

type certificateLog struct {
	Subject   string `yaml:"subject,omitempty"`
	Issuer    string `yaml:"issuer,omitempty"`
	NotBefore string `yaml:"not_before,omitempty"`
	NotAfter  string `yaml:"not_after,omitempty"`
}

type requestLog struct {
	Method      string            `yaml:"method,omitempty"`
	URL         string            `yaml:"url,omitempty"`
	Params      map[string]string `yaml:",inline"`
	Certificate *certificateLog   `yaml:"certificate,omitempty"`
	Response    any               `yaml:"response,omitempty"`
}

func requestFields(r oauth2.Request, response any) requestLog {
	params := map[string]string{}
	mergeHeaders(params, r.Headers)
	if r.URL != nil {
		mergeValues(params, r.URL.Query())
	}
	mergeValues(params, r.Form)

	out := requestLog{
		Method:   r.Method,
		URL:      requestURL(r),
		Params:   params,
		Response: response,
	}
	if r.Cert != nil {
		out.Certificate = &certificateLog{
			Subject:   r.Cert.Subject.String(),
			Issuer:    r.Cert.Issuer.String(),
			NotBefore: r.Cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  r.Cert.NotAfter.UTC().Format(time.RFC3339),
		}
	}
	return out
}

func requestURL(r oauth2.Request) string {
	if r.URL == nil {
		return ""
	}
	if r.URL.Scheme != "" {
		return fmt.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, r.URL.Path)
	}
	return r.URL.Path
}

func mergeHeaders(dst map[string]string, values map[string][]string) {
	for key, vals := range values {
		if len(vals) == 0 {
			continue
		}
		if strings.EqualFold(key, "Authorization") {
			dst[key] = redactAuthorization(vals[0])
			continue
		}
		dst[key] = strings.Join(vals, ", ")
	}
}

func redactAuthorization(value string) string {
	if len(value) >= 6 && strings.EqualFold(value[:6], "basic ") {
		return "Basic BASE64(client_id:client_secret)"
	}
	return "(redacted)"
}

func mergeValues(dst map[string]string, values map[string][]string) {
	for key, vals := range values {
		if len(vals) == 0 {
			continue
		}
		dst[key] = strings.Join(vals, ", ")
	}
}

func compactStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
