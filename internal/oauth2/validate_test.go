package oauth2

import "testing"

func validConfig() ClientConfig {
	return ClientConfig{
		IssuerURL:   "https://example.com",
		RedirectURL: "http://localhost:9876/callback",
		GrantType:   ClientCredentialsGrantType,
		ClientID:    "client",
	}
}

func TestValidateRequiresClientID(t *testing.T) {
	c := validConfig()
	c.ClientID = ""
	err := c.Validate()
	isErr(t, err)
	contains(t, err.Error(), "client id is required")
}

func TestValidateAcceptsClientCredentials(t *testing.T) {
	noErr(t, validConfig().Validate())
}

func TestValidateRequiresGrantFields(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		c := validConfig()
		c.GrantType = PasswordGrantType
		err := c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "username is required")

		c.Username = "user"
		err = c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "password is required")

		c.Password = "secret"
		noErr(t, c.Validate())
	})

	t.Run("refresh_token", func(t *testing.T) {
		c := validConfig()
		c.GrantType = RefreshTokenGrantType
		err := c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "refresh token is required")

		c.RefreshToken = "rt"
		noErr(t, c.Validate())
	})

	t.Run("jwt_bearer", func(t *testing.T) {
		c := validConfig()
		c.GrantType = JWTBearerGrantType
		err := c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "assertion is required")

		c.Assertion = `{"sub":"user"}`
		noErr(t, c.Validate())
	})

	t.Run("token_exchange", func(t *testing.T) {
		c := validConfig()
		c.GrantType = TokenExchangeGrantType
		err := c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "subject token is required")

		c.SubjectToken = "tok"
		err = c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "subject token type is required")

		c.SubjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
		noErr(t, c.Validate())
	})
}

func TestValidateRequiresAuthMethodFields(t *testing.T) {
	t.Run("client_secret_basic", func(t *testing.T) {
		c := validConfig()
		c.AuthMethod = ClientSecretBasicAuthMethod
		err := c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "client secret is required")

		c.ClientSecret = "secret"
		noErr(t, c.Validate())
	})

	t.Run("private_key_jwt", func(t *testing.T) {
		c := validConfig()
		c.AuthMethod = PrivateKeyJwtAuthMethod
		err := c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "signing key is required")

		c.SigningKey = "data/rsa/key.json"
		noErr(t, c.Validate())
	})

	t.Run("tls_client_auth", func(t *testing.T) {
		c := validConfig()
		c.AuthMethod = TLSClientAuthMethod
		err := c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "tls cert is required")

		c.TLSCert = "data/cert.pem"
		err = c.Validate()
		isErr(t, err)
		contains(t, err.Error(), "tls key is required")

		c.TLSKey = "data/key.pem"
		noErr(t, c.Validate())
	})

	t.Run("none", func(t *testing.T) {
		c := validConfig()
		c.AuthMethod = NoneAuthMethod
		noErr(t, c.Validate())
	})
}
