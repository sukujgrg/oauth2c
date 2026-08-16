package oauth2

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAuthorizeRequestResource(t *testing.T) {
	tests := map[string]struct {
		resource []string
		expected []string
	}{
		"none": {
			resource: nil,
			expected: nil,
		},
		"single": {
			resource: []string{"https://api.example.com"},
			expected: []string{"https://api.example.com"},
		},
		"multiple": {
			resource: []string{"https://api.example.com", "https://other.example.com"},
			expected: []string{"https://api.example.com", "https://other.example.com"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := &Request{}
			cconfig := ClientConfig{
				ClientID:    "test-client",
				RedirectURL: "http://localhost/callback",
				Resource:    tc.resource,
			}

			_, err := r.AuthorizeRequest(cconfig, ServerConfig{}, http.DefaultClient)
			noErr(t, err)
			eq(t, r.Form["resource"], tc.expected)
		})
	}
}

func TestAuthorizeRequestNonce(t *testing.T) {
	t.Run("unset generates nonce", func(t *testing.T) {
		r := &Request{}
		_, err := r.AuthorizeRequest(ClientConfig{
			ClientID:    "test-client",
			RedirectURL: "http://localhost/callback",
		}, ServerConfig{}, http.DefaultClient)
		noErr(t, err)
		notEmpty(t, r.Form.Get("nonce"))
		eq(t, r.Form.Get("nonce"), r.Nonce)
		eq(t, r.NonceSource, NonceSourceGenerated)
		notEmpty(t, r.Form.Get("state"))
		eq(t, r.Form.Get("state"), r.State)
	})

	tests := map[string]struct {
		nonce    string
		pkce     bool
		wantForm string
	}{
		"set": {
			nonce:    "n-0S6_WzA2Mj",
			wantForm: "n-0S6_WzA2Mj",
		},
		"set with pkce": {
			nonce:    "n-0S6_WzA2Mj",
			pkce:     true,
			wantForm: "n-0S6_WzA2Mj",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := &Request{}
			cconfig := ClientConfig{
				ClientID:    "test-client",
				RedirectURL: "http://localhost/callback",
				Nonce:       tc.nonce,
				PKCE:        tc.pkce,
			}

			codeVerifier, err := r.AuthorizeRequest(cconfig, ServerConfig{}, http.DefaultClient)
			noErr(t, err)

			eq(t, r.Form.Get("nonce"), tc.wantForm)
			eq(t, r.Nonce, tc.wantForm)
			eq(t, r.NonceSource, NonceSourceCustom)
			notEmpty(t, r.Form.Get("state"))
			eq(t, r.Form.Get("state"), r.State)

			if tc.pkce {
				notEmpty(t, codeVerifier)
				notEmpty(t, r.Form.Get("code_challenge"))
				eq(t, r.Form.Get("code_challenge_method"), "S256")
			} else {
				empty(t, codeVerifier)
				empty(t, r.Form.Get("code_challenge"))
			}
		})
	}
}

func TestRequestTokenResource(t *testing.T) {
	tests := map[string]struct {
		resource []string
		expected []string
	}{
		"none": {
			resource: nil,
			expected: nil,
		},
		"single": {
			resource: []string{"https://api.example.com"},
			expected: []string{"https://api.example.com"},
		},
		"multiple": {
			resource: []string{"https://api.example.com", "https://other.example.com"},
			expected: []string{"https://api.example.com", "https://other.example.com"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var got url.Values

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				noErr(t, err)

				got, err = url.ParseQuery(string(body))
				noErr(t, err)

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
			}))
			defer srv.Close()

			cconfig := ClientConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				GrantType:    ClientCredentialsGrantType,
				AuthMethod:   ClientSecretPostAuthMethod,
				Resource:     tc.resource,
			}
			sconfig := ServerConfig{TokenEndpoint: srv.URL}

			req, _, err := RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
			noErr(t, err)
			eq(t, req.StatusCode, http.StatusOK)
			eq(t, got["resource"], tc.expected)
		})
	}
}

func TestRequestDeviceAuthorizationNonce(t *testing.T) {
	t.Run("unset does not send nonce", func(t *testing.T) {
		var got url.Values

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			noErr(t, err)

			got, err = url.ParseQuery(string(body))
			noErr(t, err)

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_code":"dev","user_code":"user","verification_uri":"https://example.com/device","expires_in":600}`))
		}))
		defer srv.Close()

		req, _, err := RequestDeviceAuthorization(context.Background(), ClientConfig{
			ClientID: "test-client",
		}, ServerConfig{DeviceAuthorizationEndpoint: srv.URL}, &http.Client{})
		noErr(t, err)
		empty(t, got.Get("nonce"))
		empty(t, req.Nonce)
	})

	t.Run("set uses custom nonce", func(t *testing.T) {
		var got url.Values

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			noErr(t, err)

			got, err = url.ParseQuery(string(body))
			noErr(t, err)

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_code":"dev","user_code":"user","verification_uri":"https://example.com/device","expires_in":600}`))
		}))
		defer srv.Close()

		req, _, err := RequestDeviceAuthorization(context.Background(), ClientConfig{
			ClientID: "test-client",
			Nonce:    "n-0S6_WzA2Mj",
		}, ServerConfig{DeviceAuthorizationEndpoint: srv.URL}, &http.Client{})
		noErr(t, err)
		eq(t, got.Get("nonce"), "n-0S6_WzA2Mj")
		eq(t, req.Nonce, "n-0S6_WzA2Mj")
		eq(t, req.NonceSource, NonceSourceCustom)
		eq(t, req.StatusCode, http.StatusOK)
	})
}

func TestRequestTokenRecordsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized_client","error_description":"Grant type not allowed"}`))
	}))
	defer srv.Close()

	req, _, err := RequestToken(context.Background(), ClientConfig{
		ClientID:   "native",
		GrantType:  ClientCredentialsGrantType,
		AuthMethod: NoneAuthMethod,
	}, ServerConfig{TokenEndpoint: srv.URL}, &http.Client{})
	isErr(t, err)
	eq(t, req.StatusCode, http.StatusUnauthorized)
	var oe *Error
	if !errors.As(err, &oe) {
		t.Fatalf("got %T, want *Error", err)
	}
	eq(t, oe.ErrorCode, "unauthorized_client")
}

func TestAuthenticateClientMTLSEndpointAlias(t *testing.T) {
	conventional := "https://as.example.com/token"
	alias := "https://mtls.as.example.com/token"
	cconfig := ClientConfig{
		ClientID:   "test-client",
		AuthMethod: TLSClientAuthMethod,
	}

	t.Run("uses advertised alias", func(t *testing.T) {
		r := &Request{Form: url.Values{}}
		endpoint, err := r.AuthenticateClient(conventional, alias, cconfig, ServerConfig{}, clientWithTLSCert(t))
		noErr(t, err)
		eq(t, endpoint, alias)
		eq(t, r.UsedMTLSAlias, true)
		notEmpty(t, r.Cert)
	})

	t.Run("keeps conventional endpoint when alias omitted", func(t *testing.T) {
		r := &Request{Form: url.Values{}}
		endpoint, err := r.AuthenticateClient(conventional, "", cconfig, ServerConfig{}, clientWithTLSCert(t))
		noErr(t, err)
		eq(t, endpoint, conventional)
		eq(t, r.UsedMTLSAlias, false)
		notEmpty(t, r.Cert)
	})

	t.Run("keeps conventional endpoint without client certificate", func(t *testing.T) {
		r := &Request{Form: url.Values{}}
		endpoint, err := r.AuthenticateClient(conventional, alias, cconfig, ServerConfig{}, &http.Client{})
		noErr(t, err)
		eq(t, endpoint, conventional)
		eq(t, r.UsedMTLSAlias, false)
		empty(t, r.Cert)
	})
}

func clientWithTLSCert(t *testing.T) *http.Client {
	t.Helper()

	cert, err := tls.LoadX509KeyPair("../../data/cert.pem", "../../data/key.pem")
	noErr(t, err)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}
