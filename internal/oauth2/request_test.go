package oauth2

import (
	"context"
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
		notEmpty(t, r.Form.Get("state"))
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
			notEmpty(t, r.Form.Get("state"))

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

			_, _, err := RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
			noErr(t, err)
			eq(t, got["resource"], tc.expected)
		})
	}
}

func TestRequestDeviceAuthorizationNonce(t *testing.T) {
	tests := map[string]struct {
		nonce    string
		wantForm string
	}{
		"unset": {
			nonce:    "",
			wantForm: "",
		},
		"set": {
			nonce:    "n-0S6_WzA2Mj",
			wantForm: "n-0S6_WzA2Mj",
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
				_, _ = w.Write([]byte(`{"device_code":"dev","user_code":"user","verification_uri":"https://example.com/device","expires_in":600}`))
			}))
			defer srv.Close()

			cconfig := ClientConfig{
				ClientID: "test-client",
				Nonce:    tc.nonce,
			}
			sconfig := ServerConfig{DeviceAuthorizationEndpoint: srv.URL}

			req, _, err := RequestDeviceAuthorization(context.Background(), cconfig, sconfig, &http.Client{})
			noErr(t, err)
			eq(t, got.Get("nonce"), tc.wantForm)
			eq(t, req.Nonce, tc.wantForm)
		})
	}
}
