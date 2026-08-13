package cmd

import (
	"context"
	"net/http"

	"github.com/sukujgrg/oauth2c/internal/oauth2"
)

func (c *OAuth2Cmd) AuthorizationCodeGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		parRequest       oauth2.Request
		parResponse      oauth2.PARResponse
		authorizeRequest oauth2.Request
		callbackRequest  oauth2.Request
		tokenRequest     oauth2.Request
		tokenResponse    oauth2.TokenResponse
		codeVerifier     string
		err              error
	)

	if clientConfig.PAR {
		if parRequest, parResponse, authorizeRequest, codeVerifier, err = oauth2.RequestPAR(context.Background(), clientConfig, serverConfig, hc); err != nil {
			LogRequestAndResponseln(parRequest, err)
			return err
		}

		LogAssertion(parRequest, "client_assertion")
		LogAuthMethod(clientConfig)
		LogRequestObject(parRequest)
		LogRequestAndResponse(parRequest, parResponse)
		LogRequestln(authorizeRequest)
	} else {
		if authorizeRequest, codeVerifier, err = oauth2.RequestAuthorization(clientConfig, serverConfig, hc); err != nil {
			return err
		}

		LogRequestObject(authorizeRequest)
		LogRequestln(authorizeRequest)
	}

	LogPKCE(codeVerifier)
	LogAuthURL(authorizeRequest.URL.String(), clientConfig.NoBrowser)
	Logln()

	LogWaiting("callback")

	if callbackRequest, err = oauth2.WaitForCallback(clientConfig, serverConfig, hc); err != nil {
		LogRequestln(callbackRequest)
		return err
	}

	sentNonce := authorizeRequest.Nonce
	if sentNonce == "" {
		sentNonce = parRequest.Nonce
	}

	LogRequestln(callbackRequest)
	LogJARM(callbackRequest)
	if idToken := callbackRequest.Get("id_token"); idToken != "" {
		if err = CheckNonce(sentNonce, idToken, clientConfig, serverConfig, hc); err != nil {
			return err
		}
	}

	if tokenRequest, tokenResponse, err = oauth2.RequestToken(
		context.Background(),
		clientConfig,
		serverConfig,
		hc,
		oauth2.WithAuthorizationCode(callbackRequest.Get("code")),
		oauth2.WithRedirectURL(clientConfig.RedirectURL),
		oauth2.WithCodeVerifier(codeVerifier),
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)
	if err = CheckNonce(sentNonce, tokenResponse.IDToken, clientConfig, serverConfig, hc); err != nil {
		return err
	}

	c.PrintResult(tokenResponse)

	return nil
}
