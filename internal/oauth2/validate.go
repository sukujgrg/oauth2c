package oauth2

import (
	"encoding/json/v2"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

var (
	grantTypes = []string{
		AuthorizationCodeGrantType,
		ClientCredentialsGrantType,
		ImplicitGrantType,
		PasswordGrantType,
		RefreshTokenGrantType,
		JWTBearerGrantType,
		TokenExchangeGrantType,
		DeviceGrantType,
	}
	authMethods = []string{
		ClientSecretBasicAuthMethod,
		ClientSecretPostAuthMethod,
		ClientSecretJwtAuthMethod,
		PrivateKeyJwtAuthMethod,
		SelfSignedTLSAuthMethod,
		TLSClientAuthMethod,
		NoneAuthMethod,
	}
	responseTypes = []string{"code", "id_token", "token", "none"}
	responseModes = []string{"query", "form_post", "query.jwt", "form_post.jwt", "jwt"}
	tokenTypes    = []string{"urn:ietf:params:oauth:token-type:access_token"}
)

func (c ClientConfig) Validate() error {
	if err := requireURL("issuer url", c.IssuerURL); err != nil {
		return err
	}
	if err := requireURL("redirect url", c.RedirectURL); err != nil {
		return err
	}
	if c.GrantType == "" {
		return fmt.Errorf("grant type is required")
	}
	if err := optionalOneOf("grant type", c.GrantType, grantTypes); err != nil {
		return err
	}
	if err := optionalOneOf("auth method", c.AuthMethod, authMethods); err != nil {
		return err
	}
	for _, rt := range c.ResponseType {
		if err := optionalOneOf("response type", rt, responseTypes); err != nil {
			return err
		}
	}
	if err := optionalOneOf("response mode", c.ResponseMode, responseModes); err != nil {
		return err
	}
	if err := optionalJSON("assertion", c.Assertion); err != nil {
		return err
	}
	if err := optionalJSON("claims", c.Claims); err != nil {
		return err
	}
	if err := optionalJSON("rar", c.RAR); err != nil {
		return err
	}
	if err := optionalOneOf("subject token type", c.SubjectTokenType, tokenTypes); err != nil {
		return err
	}
	if err := optionalOneOf("actor token type", c.ActorTokenType, tokenTypes); err != nil {
		return err
	}

	for _, item := range [][2]string{
		{"signing key", c.SigningKey},
		{"encryption key", c.EncryptionKey},
		{"tls cert", c.TLSCert},
		{"tls key", c.TLSKey},
		{"tls root ca", c.TLSRootCA},
		{"callback tls cert", c.CallbackTLSCert},
		{"callback tls key", c.CallbackTLSKey},
	} {
		if err := optionalPathOrURI(item[0], item[1]); err != nil {
			return err
		}
	}

	return nil
}

func requireURL(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}

	u, err := url.ParseRequestURI(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must be a URL", name)
	}

	return nil
}

func optionalOneOf(name, value string, allowed []string) error {
	if value == "" {
		return nil
	}
	if !slices.Contains(allowed, value) {
		return fmt.Errorf("%s must be one of: %s", name, strings.Join(allowed, ", "))
	}
	return nil
}

func optionalJSON(name, value string) error {
	if value == "" {
		return nil
	}

	var v any
	if err := json.Unmarshal([]byte(value), &v); err != nil {
		return fmt.Errorf("%s must be JSON: %w", name, err)
	}

	return nil
}

func optionalPathOrURI(name, value string) error {
	if value == "" {
		return nil
	}

	if strings.Contains(value, "://") {
		if _, err := url.ParseRequestURI(value); err != nil {
			return fmt.Errorf("%s must be a URL or file path: %w", name, err)
		}
	}

	return nil
}
