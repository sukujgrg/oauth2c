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
			LogRequestAndResponse(parRequest, err)
			return err
		}

		LogAssertion(parRequest, "client_assertion")
		CheckMTLS(parRequest)
		LogRequestObject(parRequest)
		LogRequestAndResponse(parRequest, parResponse)
		LogRequest(authorizeRequest)
	} else {
		if authorizeRequest, codeVerifier, err = oauth2.RequestAuthorization(clientConfig, serverConfig, hc); err != nil {
			return err
		}

		LogRequestObject(authorizeRequest)
		LogRequest(authorizeRequest)
	}

	LogPKCE(codeVerifier)
	LogNonce(authorizeRequest)
	if authorizeRequest.Nonce == "" {
		LogNonce(parRequest)
	}
	LogURL("authorization_url", authorizeRequest.URL.String(), clientConfig.NoBrowser)

	LogWaiting("authorization_response")

	if callbackRequest, err = oauth2.WaitForCallback(clientConfig, serverConfig, hc, authorizeRequest.State); err != nil {
		LogRequest(callbackRequest)
		if callbackRequest.URL != nil {
			_ = CheckState(authorizeRequest.State, callbackRequest.Get("state"))
		}
		return err
	}

	sentNonce, nonceSource := nonceSent(authorizeRequest, parRequest)

	LogRequest(callbackRequest)
	LogJARM(callbackRequest)
	if err = CheckState(authorizeRequest.State, callbackRequest.Get("state")); err != nil {
		return err
	}
	if idToken := callbackRequest.Get("id_token"); idToken != "" {
		if err = CheckIDToken(sentNonce, nonceSource, idToken, clientConfig, serverConfig, hc); err != nil {
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
		LogRequestAndResponse(tokenRequest, err)
		return err
	}

	CheckMTLS(tokenRequest)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokens(tokenResponse)
	if err = CheckIDToken(sentNonce, nonceSource, tokenResponse.IDToken, clientConfig, serverConfig, hc); err != nil {
		return err
	}

	c.PrintResult(tokenResponse)

	return nil
}
