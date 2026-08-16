package oauth2

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DeviceAuthorizationResponse struct {
	DeviceCode              string  `json:"device_code"`
	UserCode                string  `json:"user_code"`
	VerificationURI         string  `json:"verification_uri"`
	VerificationURIComplete *string `json:"verification_uri_complete"`
	ExpiresIn               int64   `json:"expires_in"`
	Interval                *int64  `json:"interval"`
}

func RequestDeviceAuthorization(ctx context.Context, cconfig ClientConfig, sconfig ServerConfig, hc *http.Client) (request Request, response DeviceAuthorizationResponse, err error) {
	var (
		req  *http.Request
		resp *http.Response
	)

	if sconfig.DeviceAuthorizationEndpoint == "" {
		return request, response, fmt.Errorf("the server's device authorization endpoint is not configured")
	}

	request.Form = url.Values{
		"client_id": {cconfig.ClientID},
	}

	if len(cconfig.Scopes) > 0 {
		request.Form.Set("scope", strings.Join(cconfig.Scopes, " "))
	}

	if len(cconfig.Audience) > 0 {
		request.Form.Set("audience", strings.Join(cconfig.Audience, " "))
	}

	if cconfig.Nonce != "" {
		request.Nonce = cconfig.Nonce
		request.NonceSource = NonceSourceCustom
		request.Form.Set("nonce", cconfig.Nonce)
	}

	for _, resource := range cconfig.Resource {
		request.Form.Add("resource", resource)
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		sconfig.DeviceAuthorizationEndpoint,
		strings.NewReader(request.Form.Encode()),
	); err != nil {
		return request, response, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	request.Method = req.Method
	request.Headers = req.Header
	request.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return request, response, err
	}

	defer resp.Body.Close()
	request.StatusCode = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		return request, response, ParseError(resp)
	}

	if err = json.UnmarshalRead(resp.Body, &response); err != nil {
		return request, response, fmt.Errorf("failed to parse token response: %w", err)
	}

	return request, response, nil
}

const (
	DeviceDefaultPollInterval = 5 * time.Second
	DeviceSlowDownIncrement   = 5 * time.Second
)

// DevicePollInterval applies RFC 8628 polling backoff. authorization_pending
// retries at the current interval; slow_down increases all subsequent
// intervals by five seconds.
func DevicePollInterval(current time.Duration, err error) (time.Duration, bool) {
	var oauthErr *Error
	if !errors.As(err, &oauthErr) {
		return current, false
	}

	switch oauthErr.ErrorCode {
	case ErrAuthorizationPending:
		return current, true
	case ErrSlowDown:
		return current + DeviceSlowDownIncrement, true
	default:
		return current, false
	}
}
