package oauth2

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// grant types
const (
	AuthorizationCodeGrantType string = "authorization_code"
	ClientCredentialsGrantType string = "client_credentials"
	ImplicitGrantType          string = "implicit"
	PasswordGrantType          string = "password"
	RefreshTokenGrantType      string = "refresh_token"
	JWTBearerGrantType         string = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	TokenExchangeGrantType     string = "urn:ietf:params:oauth:grant-type:token-exchange"
	DeviceGrantType            string = "urn:ietf:params:oauth:grant-type:device_code"
)

// auth methods
const (
	ClientSecretBasicAuthMethod string = "client_secret_basic"
	ClientSecretPostAuthMethod  string = "client_secret_post"
	ClientSecretJwtAuthMethod   string = "client_secret_jwt"
	PrivateKeyJwtAuthMethod     string = "private_key_jwt"
	SelfSignedTLSAuthMethod     string = "self_signed_tls_client_auth"
	TLSClientAuthMethod         string = "tls_client_auth"
	NoneAuthMethod              string = "none"
)

// client assertion types
const (
	JwtBearerClientAssertion string = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

const CodeVerifierLength = 43

var CodeChallengeEncoder = base64.RawURLEncoding

type ClientConfig struct {
	IssuerURL              string
	RedirectURL            string
	NoOrigin               bool
	GrantType              string
	ClientID               string
	ClientSecret           string
	Scopes                 []string
	ACRValues              []string
	Audience               []string
	Resource               []string
	AuthMethod             string
	PKCE                   bool
	Nonce                  string
	PAR                    bool
	RequestObject          bool
	EncryptedRequestObject bool
	Insecure               bool
	ResponseType           []string
	ResponseMode           string
	Username               string
	Password               string
	RefreshToken           string
	Assertion              string
	SigningKey             string
	EncryptionKey          string
	SubjectToken           string
	SubjectTokenType       string
	ActorToken             string
	ActorTokenType         string
	IDTokenHint            string
	LoginHint              string
	IDPHint                string
	TLSCert                string
	TLSKey                 string
	TLSRootCA              string
	CallbackTLSCert        string
	CallbackTLSKey         string
	CallbackAddr           string
	HTTPTimeout            time.Duration
	BrowserTimeout         time.Duration
	NoBrowser              bool
	DPoP                   bool
	Claims                 string
	RAR                    string
	Purpose                string
	Prompt                 []string
	MaxAge                 string
	AuthenticationCode     string
}

func RequestAuthorization(cconfig ClientConfig, sconfig ServerConfig, hc *http.Client) (r Request, codeVerifier string, err error) {
	if sconfig.AuthorizationEndpoint == "" {
		return r, "", errors.New("the server's authorization endpoint is not configured")
	}

	if r.URL, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return r, "", fmt.Errorf("failed to parse authorization endpoint: %w", err)
	}

	if codeVerifier, err = r.AuthorizeRequest(cconfig, sconfig, hc); err != nil {
		return r, "", fmt.Errorf("failed to create authorization request: %w", err)
	}

	r.URL.RawQuery = r.Form.Encode()
	r.Method = http.MethodGet
	r.Form = url.Values{}

	return r, codeVerifier, nil
}

type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

func RequestPAR(
	ctx context.Context,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
) (parRequest Request, parResponse PARResponse, authorizeRequest Request, codeVerifier string, err error) {
	var (
		req      *http.Request
		resp     *http.Response
		endpoint string
	)

	if sconfig.AuthorizationEndpoint == "" {
		return parRequest, parResponse, authorizeRequest, "", errors.New("the server's authorization endpoint is not configured")
	}

	if sconfig.PushedAuthorizationRequestEndpoint == "" && sconfig.MTLsEndpointAliases.PushedAuthorizationRequestEndpoint == "" {
		return parRequest, parResponse, authorizeRequest, "", errors.New("the server's pushed authorization request endpoint is not configured")
	}

	// push authorization request to /par
	if codeVerifier, err = parRequest.AuthorizeRequest(cconfig, sconfig, hc); err != nil {
		return parRequest, parResponse, authorizeRequest, "", fmt.Errorf("failed to create authorization request: %w", err)
	}

	if endpoint, err = parRequest.AuthenticateClient(
		sconfig.PushedAuthorizationRequestEndpoint,
		sconfig.MTLsEndpointAliases.PushedAuthorizationRequestEndpoint,
		cconfig,
		sconfig,
		hc,
	); err != nil {
		return parRequest, parResponse, authorizeRequest, "", fmt.Errorf("failed to create client authentication request: %w", err)
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(parRequest.Form.Encode()),
	); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, err
	}

	if cconfig.AuthMethod == ClientSecretBasicAuthMethod {
		req.SetBasicAuth(cconfig.ClientID, cconfig.ClientSecret)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	parRequest.Method = req.Method
	parRequest.Headers = req.Header
	parRequest.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return parRequest, parResponse, authorizeRequest, codeVerifier, ParseError(resp)
	}

	if err = json.UnmarshalRead(resp.Body, &parResponse); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, fmt.Errorf("failed to parse token response: %w", err)
	}

	// build request to /authorize
	if authorizeRequest.URL, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, fmt.Errorf("failed to create authorization request: %w", err)
	}

	values := url.Values{
		"client_id":   {cconfig.ClientID},
		"request_uri": {parResponse.RequestURI},
	}

	authorizeRequest.URL.RawQuery = values.Encode()
	authorizeRequest.Method = http.MethodGet

	return parRequest, parResponse, authorizeRequest, codeVerifier, nil
}

func WaitForCallback(clientConfig ClientConfig, serverConfig ServerConfig, hc *http.Client) (Request, error) {
	var (
		redirectURL *url.URL
		cert        tls.Certificate
		done        = make(chan struct{})
		mu          sync.Mutex
		result      Request
		resultErr   error
		err         error
	)

	if redirectURL, err = url.Parse(clientConfig.RedirectURL); err != nil {
		return Request{}, fmt.Errorf("failed to parse redirect url: %s: %w", clientConfig.RedirectURL, err)
	}

	if redirectURL.Path == "" {
		redirectURL.Path = "/"
	}

	useTLS := clientConfig.CallbackTLSCert != "" && clientConfig.CallbackTLSKey != ""

	addr := clientConfig.CallbackAddr
	if addr == "" {
		addr = redirectURL.Host
		if redirectURL.Port() == "" {
			if useTLS {
				addr += ":443"
			} else {
				addr += ":80"
			}
		}
	}

	mux := http.NewServeMux()
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if useTLS {
		if cert, err = ReadKeyPair(clientConfig.CallbackTLSCert, clientConfig.CallbackTLSKey, hc); err != nil {
			return Request{}, fmt.Errorf("failed to read callback tls key pair: %w", err)
		}

		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	shutdown := func() {
		time.AfterFunc(time.Second, func() {
			_ = srv.Shutdown(context.Background())
		})
	}

	mux.HandleFunc(redirectURL.Path, func(w http.ResponseWriter, r *http.Request) {
		defer shutdown()

		var (
			req Request
			err error
		)

		if err = r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			mu.Lock()
			resultErr = err
			mu.Unlock()
			return
		}

		req.Method = r.Method
		req.URL = r.URL
		req.Form = r.PostForm

		if req.Get("response") != "" {
			var (
				signingKey    jose.JSONWebKey
				encryptionKey jose.JSONWebKey
			)

			if signingKey, err = ReadKey(SigningKey, serverConfig.JWKsURI, hc); err != nil {
				http.Error(w, "failed to read signing key", http.StatusBadRequest)
				mu.Lock()
				resultErr = err
				mu.Unlock()
				return
			}

			if clientConfig.EncryptionKey != "" {
				if encryptionKey, err = ReadKey(EncryptionKey, clientConfig.EncryptionKey, hc); err != nil {
					http.Error(w, "failed to read encryption key", http.StatusBadRequest)
					mu.Lock()
					resultErr = err
					mu.Unlock()
					return
				}
			}

			if err = req.ParseJARM(signingKey, encryptionKey); err != nil {
				http.Error(w, "failed to parse JARM response", http.StatusBadRequest)
				mu.Lock()
				resultErr = err
				mu.Unlock()
				return
			}
		}

		w.Header().Set("Content-Type", "text/html")

		if req.Get("error") != "" {
			err = &Error{
				ErrorCode:   req.Get("error"),
				Description: req.Get("error_description"),
				Hint:        req.Get("error_hint"),
				TraceID:     req.Get("trace_id"),
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<script>window.close()</script> Authorization failed. You may close this window.`))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<script>window.close()</script> Authorization succeeded. You may close this window.`))
		}

		mu.Lock()
		result = req
		if resultErr == nil {
			resultErr = err
		}
		mu.Unlock()
	})

	go func() {
		defer close(done)

		var serr error
		if useTLS {
			serr = srv.ListenAndServeTLS("", "")
		} else {
			serr = srv.ListenAndServe()
		}
		if serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			mu.Lock()
			if resultErr == nil {
				resultErr = serr
			}
			mu.Unlock()
		}
	}()

	select {
	case <-time.After(clientConfig.BrowserTimeout):
		_ = srv.Shutdown(context.Background())
		return Request{}, errors.New("timeout")
	case <-done:
		mu.Lock()
		defer mu.Unlock()
		return result, resultErr
	}
}

type TokenResponse struct {
	AccessToken          string           `json:"access_token,omitempty"`
	ExpiresIn            FlexibleInt64    `json:"expires_in,omitempty"`
	IDToken              string           `json:"id_token,omitempty"`
	IssuedTokenType      string           `json:"issued_token_type,omitempty"`
	RefreshToken         string           `json:"refresh_token,omitempty"`
	Scope                string           `json:"scope,omitempty"`
	TokenType            string           `json:"token_type,omitempty"`
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`

	raw map[string]jsontext.Value
}

type tokenResponseAlias TokenResponse

func (t *TokenResponse) UnmarshalJSON(data []byte) error {
	var typed tokenResponseAlias

	if err := json.Unmarshal(data, &typed); err != nil {
		return err
	}

	*t = TokenResponse(typed)

	return json.Unmarshal(data, &t.raw)
}

func (t TokenResponse) MarshalJSON() ([]byte, error) {
	var typedMap map[string]jsontext.Value

	typed, err := json.Marshal(tokenResponseAlias(t))
	if err != nil {
		return nil, err
	}

	if len(t.raw) == 0 {
		return typed, nil
	}

	if err := json.Unmarshal(typed, &typedMap); err != nil {
		return nil, err
	}

	out := make(map[string]jsontext.Value, len(t.raw))

	maps.Copy(out, t.raw)
	maps.Copy(out, typedMap)

	return json.Marshal(out)
}

type FlexibleInt64 int64

func (f *FlexibleInt64) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = 0
		return nil
	}

	// check if we have a number in a string, and parse it if so
	if b[0] == '"' {
		var s string

		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}

		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}

		*f = FlexibleInt64(i)
		return nil
	}

	var i int64

	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}

	*f = FlexibleInt64(i)

	return nil
}

func NewTokenResponseFromForm(f url.Values) TokenResponse {
	expiresIn, _ := strconv.ParseInt(f.Get("expires_in"), 10, 64)

	return TokenResponse{
		AccessToken:     f.Get("access_token"),
		ExpiresIn:       FlexibleInt64(expiresIn),
		IDToken:         f.Get("id_token"),
		IssuedTokenType: f.Get("issued_token_type"),
		RefreshToken:    f.Get("refresh_token"),
		Scope:           f.Get("scope"),
		TokenType:       f.Get("token_type"),
	}
}

type RequestTokenParams struct {
	Code         string
	DeviceCode   string
	CodeVerifier string
	RedirectURL  string
}

type RequestTokenOption func(*RequestTokenParams)

func WithAuthorizationCode(code string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.Code = code
	}
}

func WithDeviceCode(deviceCode string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.DeviceCode = deviceCode
	}
}

func WithCodeVerifier(codeVerifier string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.CodeVerifier = codeVerifier
	}
}

func WithRedirectURL(url string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.RedirectURL = url
	}
}

func RequestToken(
	ctx context.Context,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
	opts ...RequestTokenOption,
) (request Request, response TokenResponse, err error) {
	var (
		req         *http.Request
		resp        *http.Response
		params      RequestTokenParams
		redirectURL *url.URL
		endpoint    string
		body        []byte
	)

	if sconfig.TokenEndpoint == "" && sconfig.MTLsEndpointAliases.TokenEndpoint == "" {
		return request, response, errors.New("the server's token endpoint is not configured")
	}

	for _, opt := range opts {
		opt(&params)
	}

	request.Form = url.Values{
		"grant_type": {cconfig.GrantType},
	}

	switch cconfig.GrantType {
	case ClientCredentialsGrantType, PasswordGrantType, RefreshTokenGrantType, JWTBearerGrantType, TokenExchangeGrantType:
		if len(cconfig.Scopes) > 0 {
			request.Form.Set("scope", strings.Join(cconfig.Scopes, " "))
		}

		if len(cconfig.Audience) > 0 {
			request.Form.Set("audience", strings.Join(cconfig.Audience, " "))
		}

		for _, resource := range cconfig.Resource {
			request.Form.Add("resource", resource)
		}

		if len(cconfig.RAR) > 0 {
			request.Form.Set("authorization_details", cconfig.RAR)
		}
	}

	switch cconfig.GrantType {
	case PasswordGrantType:
		request.Form.Set("username", cconfig.Username)
		request.Form.Set("password", cconfig.Password)
	case RefreshTokenGrantType:
		request.Form.Set("refresh_token", cconfig.RefreshToken)
	case JWTBearerGrantType:
		var assertion string

		if assertion, request.SigningKey, err = SignJWT(
			AssertionClaims(sconfig, cconfig),
			JWKSigner(cconfig.SigningKey, hc),
		); err != nil {
			return request, response, err
		}

		request.Form.Set("assertion", assertion)
	case TokenExchangeGrantType:
		request.Form.Set("subject_token", cconfig.SubjectToken)
		request.Form.Set("subject_token_type", cconfig.SubjectTokenType)

		if cconfig.ActorToken != "" {
			request.Form.Set("actor_token", cconfig.ActorToken)
			request.Form.Set("actor_token_type", cconfig.ActorTokenType)
		}
	case DeviceGrantType:
		request.Form.Set("device_code", params.DeviceCode)
	}

	if endpoint, err = request.AuthenticateClient(
		sconfig.TokenEndpoint,
		sconfig.MTLsEndpointAliases.TokenEndpoint,
		cconfig,
		sconfig,
		hc,
	); err != nil {
		return request, response, err
	}

	if params.RedirectURL != "" {
		request.Form.Set("redirect_uri", params.RedirectURL)
	}

	if params.Code != "" {
		request.Form.Set("code", params.Code)
	}

	if params.CodeVerifier != "" {
		request.Form.Set("code_verifier", params.CodeVerifier)
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(request.Form.Encode()),
	); err != nil {
		return request, response, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if cconfig.AuthMethod == ClientSecretBasicAuthMethod {
		req.SetBasicAuth(cconfig.ClientID, cconfig.ClientSecret)
	}

	if cconfig.RedirectURL != "" && cconfig.AuthMethod == NoneAuthMethod {
		if redirectURL, err = url.Parse(cconfig.RedirectURL); err != nil {
			return request, response, err
		}

		if !cconfig.NoOrigin {
			req.Header.Add("Origin", fmt.Sprintf("%s://%s", redirectURL.Scheme, redirectURL.Host))
		}
	}

	if cconfig.DPoP {
		if err = DPoPSignRequest(cconfig.SigningKey, hc, req); err != nil {
			return request, response, err
		}
	}

	request.Method = req.Method
	request.Headers = req.Header
	request.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return request, response, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return request, response, ParseError(resp)
	}

	if body, err = io.ReadAll(resp.Body); err != nil {
		return request, response, fmt.Errorf("failed to read exchange response body: %w", err)
	}

	if err = json.Unmarshal(body, &response); err != nil {
		return request, response, fmt.Errorf("failed to parse exchange response: %w", err)
	}

	return request, response, nil
}
