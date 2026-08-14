package cmd

import (
	"testing"

	"github.com/sukujgrg/oauth2c/internal/oauth2"
)

func TestOAuth2NonBrowserGrantTypes(t *testing.T) {
	env := requireAuth0(t)

	testcases := []CommandTestCase{
		{
			title: "resource_owner",
			args: []string{
				env.Issuer,
				"--client-id", env.WebID,
				"--client-secret", env.WebSecret,
				"--grant-type", oauth2.PasswordGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--username", env.Username,
				"--password", env.Password,
				"--audience", env.Audience,
				"--scopes", "openid",
				"--silent",
			},
		},
		{
			title: "refresh_token",
			args: []string{
				env.Issuer,
				"--client-id", env.WebID,
				"--client-secret", env.WebSecret,
				"--grant-type", oauth2.RefreshTokenGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--refresh-token", "$REFRESH_TOKEN",
				"--silent",
			},
			deps: map[string]CommandDependency{
				"REFRESH_TOKEN": {
					args: []string{
						env.Issuer,
						"--client-id", env.WebID,
						"--client-secret", env.WebSecret,
						"--grant-type", oauth2.PasswordGrantType,
						"--auth-method", oauth2.ClientSecretBasicAuthMethod,
						"--username", env.Username,
						"--password", env.Password,
						"--audience", env.Audience,
						"--scopes", "openid,offline_access",
						"--silent",
					},
					field: "refresh_token",
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, tc.Test())
	}
}

func TestOAuth2ClientAuthenticationMethods(t *testing.T) {
	env := requireAuth0(t)

	testcases := []CommandTestCase{
		{
			title: "client_secret_basic",
			args: []string{
				env.Issuer,
				"--client-id", env.WebID,
				"--client-secret", env.WebSecret,
				"--grant-type", oauth2.ClientCredentialsGrantType,
				"--auth-method", oauth2.ClientSecretBasicAuthMethod,
				"--audience", env.Audience,
				"--scopes", env.Scope,
				"--silent",
			},
		},
		{
			title: "client_secret_post",
			args: []string{
				env.Issuer,
				"--client-id", env.PostID,
				"--client-secret", env.PostSecret,
				"--grant-type", oauth2.ClientCredentialsGrantType,
				"--auth-method", oauth2.ClientSecretPostAuthMethod,
				"--audience", env.Audience,
				"--scopes", env.Scope,
				"--silent",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.title, tc.Test())
	}
}
