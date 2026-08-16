package cmd

import (
	"crypto/subtle"
	"encoding/json/v2"
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
)

// trace is the JSON-lines protocol log on stderr. --silent discards it
// so only the token JSON on stdout remains.
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

func (l *stderrLog) doc(v any) {
	if !l.enabled() {
		return
	}
	if err := writeJSON(l.writer(), v); err != nil {
		l.error(err)
	}
}

func (l *stderrLog) error(err error) {
	if err == nil || !l.enabled() {
		return
	}
	event := map[string]any{"error": err.Error()}
	if writeErr := writeJSON(l.writer(), event); writeErr != nil {
		_, _ = fmt.Fprintf(l.writer(), "{\"error\":%q}\n", err.Error())
	}
}

func writeJSON(w io.Writer, v any) error {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	if len(out) == 0 || string(out) == "{}" || string(out) == "null" {
		return nil
	}
	_, err = fmt.Fprintln(w, string(out))
	return err
}

func fromJSON(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	return generic, nil
}

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
		generic, err = fromJSON(response)
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
	IssuerURL              string   `json:"issuer_url,omitempty"`
	ClientID               string   `json:"client_id,omitempty"`
	ClientSecret           string   `json:"client_secret,omitempty"`
	GrantType              string   `json:"grant_type,omitempty"`
	AuthMethod             string   `json:"auth_method,omitempty"`
	ResponseTypes          []string `json:"response_types,omitempty"`
	ResponseMode           string   `json:"response_mode,omitempty"`
	RedirectURL            string   `json:"redirect_url,omitempty"`
	Scopes                 []string `json:"scopes,omitempty"`
	Audience               []string `json:"audience,omitempty"`
	Resource               []string `json:"resource,omitempty"`
	ACRValues              []string `json:"acr_values,omitempty"`
	PKCE                   bool     `json:"pkce,omitempty"`
	PAR                    bool     `json:"par,omitempty"`
	RequestObject          bool     `json:"request_object,omitempty"`
	EncryptedRequestObject bool     `json:"encrypted_request_object,omitempty"`
	DPoP                   bool     `json:"dpop,omitempty"`
	Nonce                  string   `json:"nonce,omitempty"`
	Username               string   `json:"username,omitempty"`
	Password               string   `json:"password,omitempty"`
	RefreshToken           string   `json:"refresh_token,omitempty"`
	SigningKey             string   `json:"signing_key,omitempty"`
	SubjectTokenType       string   `json:"subject_token_type,omitempty"`
	ActorTokenType         string   `json:"actor_token_type,omitempty"`
	IDTokenHint            string   `json:"id_token_hint,omitempty"`
	LoginHint              string   `json:"login_hint,omitempty"`
	IDPHint                string   `json:"idp_hint,omitempty"`
	Claims                 string   `json:"claims,omitempty"`
	RAR                    string   `json:"rar,omitempty"`
	Prompt                 []string `json:"prompt,omitempty"`
	MaxAge                 string   `json:"max_age,omitempty"`
	Purpose                string   `json:"purpose,omitempty"`
	AuthenticationCode     string   `json:"authentication_code,omitempty"`
	TLSCert                string   `json:"tls_cert,omitempty"`
	TLSKey                 string   `json:"tls_key,omitempty"`
	TLSRootCA              string   `json:"tls_root_ca,omitempty"`
}

type nonceLog struct {
	Spec    string `json:"spec,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	Source  string `json:"source,omitempty"`
	Value   string `json:"value,omitempty"`
}

type pkceLog struct {
	Spec          string `json:"spec,omitempty"`
	Purpose       string `json:"purpose,omitempty"`
	CodeVerifier  string `json:"code_verifier,omitempty"`
	CodeChallenge string `json:"code_challenge,omitempty"`
}

type signedJWTLog struct {
	Encoding string         `json:"encoding"`
	Claims   map[string]any `json:"-"`
}

func (s signedJWTLog) MarshalJSON() ([]byte, error) {
	m := map[string]any{"encoding": s.Encoding}
	for k, v := range s.Claims {
		m[k] = v
	}
	return json.Marshal(m)
}

type certificateLog struct {
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

type requestLog struct {
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	Params      map[string]string `json:"-"`
	Certificate *certificateLog   `json:"certificate,omitempty"`
	Response    any               `json:"response,omitempty"`
}

func (r requestLog) MarshalJSON() ([]byte, error) {
	m := map[string]any{}
	if r.Method != "" {
		m["method"] = r.Method
	}
	if r.URL != "" {
		m["url"] = r.URL
	}
	for k, v := range r.Params {
		m[k] = v
	}
	if r.Certificate != nil {
		m["certificate"] = r.Certificate
	}
	if r.Response != nil {
		m["response"] = r.Response
	}
	return json.Marshal(m)
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
