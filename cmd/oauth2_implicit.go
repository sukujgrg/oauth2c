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

	LogRequestln(authorizeRequest)
	LogAuthURL(authorizeRequest.URL.String(), clientConfig.NoBrowser)
	Logln()

	LogWaiting("callback")

	if callbackRequest, err = oauth2.WaitForCallback(clientConfig, serverConfig, hc); err != nil {
		LogRequestln(callbackRequest)
		return err
	}

	tokenResponse := oauth2.NewTokenResponseFromForm(callbackRequest.Form)
	if tokenResponse.IDToken == "" {
		tokenResponse.IDToken = callbackRequest.Get("id_token")
	}

	LogRequestln(callbackRequest)
	LogTokenPayloadln(tokenResponse)
	if err = CheckNonce(authorizeRequest.Nonce, tokenResponse.IDToken, clientConfig, serverConfig, hc); err != nil {
		return err
	}

	c.PrintResult(tokenResponse)

	return nil
}
