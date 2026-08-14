package cmd

import (
	"context"
	"net/http"
	"time"

	"github.com/sukujgrg/oauth2c/internal/oauth2"
)

func (c *OAuth2Cmd) DeviceGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizationRequest  oauth2.Request
		authorizationResponse oauth2.DeviceAuthorizationResponse
		tokenRequest          oauth2.Request
		tokenResponse         oauth2.TokenResponse
		err                   error
	)

	if authorizationRequest, authorizationResponse, err = oauth2.RequestDeviceAuthorization(context.Background(), clientConfig, serverConfig, hc); err != nil {
		LogRequestAndResponse(authorizationRequest, err)
		return err
	}

	LogRequestAndResponse(authorizationRequest, authorizationResponse)
	LogNonce(authorizationRequest)

	verificationUri := authorizationResponse.VerificationURI
	if authorizationResponse.VerificationURIComplete != nil {
		verificationUri = *authorizationResponse.VerificationURIComplete
	}

	LogURL("verification_url", verificationUri, clientConfig.NoBrowser)

	LogWaiting("device_authorization")

	interval := oauth2.DeviceDefaultPollInterval
	if authorizationResponse.Interval != nil {
		interval = time.Duration(*authorizationResponse.Interval) * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	done := make(chan error)

	go func() {
		defer close(done)

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if tokenRequest, tokenResponse, err = oauth2.RequestToken(
					context.Background(),
					clientConfig,
					serverConfig,
					hc,
					oauth2.WithDeviceCode(authorizationResponse.DeviceCode),
				); err != nil {
					next, retry := oauth2.DevicePollInterval(interval, err)
					if retry {
						if next != interval {
							interval = next
							ticker.Reset(interval)
							CheckDeviceSlowDown(oauth2.ErrSlowDown, interval)
						}
						continue
					}

					done <- err
					return
				}

				return
			}
		}
	}()

	err = <-done

	if err != nil {
		LogRequestAndResponse(tokenRequest, err)
		return err
	}

	CheckMTLS(tokenRequest)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokens(tokenResponse)
	if err = CheckIDToken(authorizationRequest.Nonce, authorizationRequest.NonceSource, tokenResponse.IDToken, clientConfig, serverConfig, hc); err != nil {
		return err
	}

	c.PrintResult(tokenResponse)

	return nil
}
