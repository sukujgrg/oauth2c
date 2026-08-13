package cmd

import (
	"context"
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func (c *OAuth2Cmd) ClientCredentialsGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow(clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) PasswordGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow(clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) RefreshTokenGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow(clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) JWTBearerGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow(clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) TokenExchangeGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow(clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) tokenEndpointFlow(
	clientConfig oauth2.ClientConfig,
	serverConfig oauth2.ServerConfig,
	hc *http.Client,
	requestTokenOpts ...oauth2.RequestTokenOption,
) error {

	var (
		tokenRequest  oauth2.Request
		tokenResponse oauth2.TokenResponse
		err           error
	)

	if tokenRequest, tokenResponse, err = oauth2.RequestToken(
		context.Background(),
		clientConfig,
		serverConfig,
		hc,
		requestTokenOpts...,
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogAssertion(tokenRequest, "assertion")
	LogAssertion(tokenRequest, "client_assertion")
	LogSubjectTokenAndActorToken(tokenRequest)
	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	c.PrintResult(tokenResponse)

	return nil
}
