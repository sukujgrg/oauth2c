package cmd

import (
	"net/http"

	"github.com/sukujgrg/oauth2c/internal/oauth2"
)

func (c *OAuth2Cmd) ImplicitGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		err              error
	)

	if authorizeRequest, _, err = oauth2.RequestAuthorization(clientConfig, serverConfig, hc); err != nil {
		return err
	}

	LogRequest(authorizeRequest)
	LogNonce(authorizeRequest)
	LogURL("authorization_url", authorizeRequest.URL.String(), clientConfig.NoBrowser)

	LogWaiting("authorization_response")

	if callbackRequest, err = oauth2.WaitForCallback(clientConfig, serverConfig, hc, authorizeRequest.State); err != nil {
		LogRequest(callbackRequest)
		if callbackRequest.URL != nil {
			_ = CheckState(authorizeRequest.State, callbackRequest.Get("state"))
		}
		return err
	}

	tokenResponse := oauth2.NewTokenResponseFromForm(callbackRequest.Form)
	if tokenResponse.IDToken == "" {
		tokenResponse.IDToken = callbackRequest.Get("id_token")
	}

	LogRequest(callbackRequest)
	LogTokens(tokenResponse)
	if err = CheckState(authorizeRequest.State, callbackRequest.Get("state")); err != nil {
		return err
	}
	if err = CheckIDToken(authorizeRequest.Nonce, authorizeRequest.NonceSource, tokenResponse.IDToken, clientConfig, serverConfig, hc); err != nil {
		return err
	}

	c.PrintResult(tokenResponse)

	return nil
}
