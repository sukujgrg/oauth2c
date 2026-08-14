package oauth2

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func UnsafeParseJWT(token string) (*jwt.JSONWebToken, map[string]interface{}, error) {
	var (
		t      *jwt.JSONWebToken
		claims = map[string]interface{}{}
		err    error
	)

	if t, err = jwt.ParseSigned(token, JOSESignatureAlgorithms); err != nil {
		return nil, nil, err
	}

	if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, err
	}

	return t, claims, nil
}

var (
	ErrIDTokenNonceMissing  = errors.New("id token nonce claim is missing")
	ErrIDTokenNonceMismatch = errors.New("id token nonce does not match")
)

func VerifyIDToken(idToken string, sconfig ServerConfig, cconfig ClientConfig, hc *http.Client) (map[string]interface{}, []Verification, error) {
	token, err := jwt.ParseSigned(idToken, JOSESignatureAlgorithms)
	if err != nil {
		return nil, []Verification{failCheck("id_token.signature", oidcCoreSpec, "token authenticity", err.Error())}, fmt.Errorf("failed to parse id token: %w", err)
	}

	var (
		keys       jose.JSONWebKeySet
		registered jwt.Claims
		claims     = map[string]interface{}{}
		hmacKey    []byte
	)

	if sconfig.JWKsURI != "" {
		if keys, err = ReadKeySet(sconfig.JWKsURI, hc); err != nil {
			return nil, []Verification{failCheck("id_token.signature", oidcCoreSpec, "token authenticity", err.Error())}, fmt.Errorf("failed to verify id token signature: %w", err)
		}
	}

	if cconfig.ClientSecret != "" {
		hmacKey = []byte(cconfig.ClientSecret)
	}

	if err = verifyIDTokenSignature(token, keys, hmacKey, &registered, &claims); err != nil {
		return nil, []Verification{failCheck("id_token.signature", oidcCoreSpec, "token authenticity", err.Error())}, err
	}

	checks := []Verification{passCheck("id_token.signature", oidcCoreSpec, "token authenticity")}
	claimChecks, err := validateIDTokenClaims(registered, claims, sconfig, cconfig)
	checks = append(checks, claimChecks...)
	return claims, checks, err
}

func verifyIDTokenSignature(token *jwt.JSONWebToken, keys jose.JSONWebKeySet, hmacKey []byte, dest ...interface{}) error {
	var verifyErr error

	if len(keys.Keys) > 0 {
		kid := ""
		if len(token.Headers) > 0 {
			kid = token.Headers[0].KeyID
		}

		if kid != "" {
			if err := token.Claims(&keys, dest...); err == nil {
				return nil
			} else {
				verifyErr = err
			}
		} else {
			sigKeys := signingKeys(keys)
			switch len(sigKeys) {
			case 1:
				if err := token.Claims(sigKeys[0], dest...); err == nil {
					return nil
				} else {
					verifyErr = err
				}
			case 0:
				verifyErr = errors.New("jwks has no signing keys")
			default:
				verifyErr = errors.New("id token has no kid and JWKS has multiple signing keys")
			}
		}
	}

	if len(hmacKey) > 0 {
		if err := token.Claims(hmacKey, dest...); err == nil {
			return nil
		} else {
			verifyErr = err
		}
	}

	if verifyErr != nil {
		return fmt.Errorf("failed to verify id token signature: %w", verifyErr)
	}

	return errors.New("failed to verify id token signature: no jwks_uri or client secret")
}

func signingKeys(set jose.JSONWebKeySet) []jose.JSONWebKey {
	var keys []jose.JSONWebKey

	for _, key := range set.Keys {
		if key.Use == "" || key.Use == string(SigningKey) {
			keys = append(keys, key)
		}
	}

	return keys
}

const oidcCoreSpec = "OpenID Connect Core"

func validateIDTokenClaims(registered jwt.Claims, claims map[string]interface{}, sconfig ServerConfig, cconfig ClientConfig) ([]Verification, error) {
	switch {
	case registered.Issuer == "":
		return []Verification{failCheck("id_token.iss", oidcCoreSpec, "issuer identification", "id token iss claim is missing")}, errors.New("id token iss claim is missing")
	case len(registered.Audience) == 0:
		return []Verification{failCheck("id_token.aud", oidcCoreSpec, "audience restriction", "id token aud claim is missing")}, errors.New("id token aud claim is missing")
	case registered.Expiry == nil:
		return []Verification{failCheck("id_token.exp", oidcCoreSpec, "expiration", "id token exp claim is missing")}, errors.New("id token exp claim is missing")
	case registered.IssuedAt == nil:
		return []Verification{failCheck("id_token.iat", oidcCoreSpec, "issued-at", "id token iat claim is missing")}, errors.New("id token iat claim is missing")
	}

	issuer := sconfig.Issuer
	if issuer == "" {
		issuer = cconfig.IssuerURL
	}

	issCheck := passCheck("id_token.iss", oidcCoreSpec, "issuer identification")
	issCheck.Expected = issuer
	issCheck.Received = registered.Issuer
	if issuer != "" && registered.Issuer != issuer {
		issCheck.Result = CheckFail
	}

	audCheck := passCheck("id_token.aud", oidcCoreSpec, "audience restriction")
	audCheck.Expected = cconfig.ClientID
	audCheck.Received = strings.Join(registered.Audience, ", ")
	if cconfig.ClientID != "" && !registered.Audience.Contains(cconfig.ClientID) {
		audCheck.Result = CheckFail
	}

	extra := extraAudiences(registered.Audience, cconfig.ClientID)
	extraCheck := passCheck("id_token.extra_audiences", oidcCoreSpec, "reject untrusted additional audiences")
	if len(extra) == 0 {
		extraCheck.Received = "none"
	} else {
		extraCheck.Received = strings.Join(extra, ", ")
		extraCheck.Result = CheckFail
		extraCheck.Detail = "id token contains untrusted additional audiences: " + extraCheck.Received
	}

	azp, _ := claims["azp"].(string)
	azpCheck := azpVerification(azp, registered.Audience, cconfig.ClientID)

	expCheck := passCheck("id_token.exp", oidcCoreSpec, "expiration")
	expCheck.Received = registered.Expiry.Time().UTC().Format(time.RFC3339)

	iatCheck := passCheck("id_token.iat", oidcCoreSpec, "issued-at")
	iatCheck.Received = registered.IssuedAt.Time().UTC().Format(time.RFC3339)

	var nbfCheck *Verification
	if registered.NotBefore != nil {
		check := passCheck("id_token.nbf", oidcCoreSpec, "not-before")
		check.Received = registered.NotBefore.Time().UTC().Format(time.RFC3339)
		nbfCheck = &check
	}

	expected := jwt.Expected{Time: time.Now()}
	if issuer != "" {
		expected.Issuer = issuer
	}
	if cconfig.ClientID != "" {
		expected.AnyAudience = jwt.Audience{cconfig.ClientID}
	}

	validateErr := registered.Validate(expected)
	if validateErr != nil {
		switch {
		case errors.Is(validateErr, jwt.ErrInvalidIssuer):
			issCheck.Result = CheckFail
		case errors.Is(validateErr, jwt.ErrInvalidAudience):
			audCheck.Result = CheckFail
		case errors.Is(validateErr, jwt.ErrExpired):
			expCheck.Result = CheckFail
		case errors.Is(validateErr, jwt.ErrIssuedInTheFuture):
			iatCheck.Result = CheckFail
			iatCheck.Detail = "id token iat is in the future"
		case errors.Is(validateErr, jwt.ErrNotValidYet):
			check := failCheck("id_token.nbf", oidcCoreSpec, "not-before", "id token is not valid yet")
			if nbfCheck != nil {
				check.Received = nbfCheck.Received
			}
			nbfCheck = &check
		}
	}

	checks := []Verification{issCheck, audCheck, extraCheck, azpCheck, expCheck, iatCheck}
	if nbfCheck != nil {
		checks = append(checks, *nbfCheck)
	}

	for _, check := range checks {
		if check.Result != CheckFail {
			continue
		}
		if validateErr != nil {
			return checks, fmt.Errorf("id token claims are invalid: %w", validateErr)
		}
		if check.Detail != "" {
			return checks, errors.New(check.Detail)
		}
		return checks, fmt.Errorf("%s failed", check.Name)
	}
	if validateErr != nil {
		return checks, fmt.Errorf("id token claims are invalid: %w", validateErr)
	}

	return checks, nil
}

func azpVerification(azp string, aud jwt.Audience, clientID string) Verification {
	check := passCheck("id_token.azp", oidcCoreSpec, "authorized party")
	check.Expected = clientID

	switch {
	case azp == "" && len(aud) > 1:
		check.Received = "(missing)"
		check.Result = CheckFail
		check.Detail = "id token azp claim is missing"
	case azp == "":
		check.Expected = "(not required)"
		check.Received = "(not present)"
	case clientID != "" && azp != clientID:
		check.Received = azp
		check.Result = CheckFail
		check.Detail = fmt.Sprintf("id token azp %q does not match client_id %q", azp, clientID)
	default:
		check.Received = azp
	}

	return check
}

func extraAudiences(aud jwt.Audience, clientID string) []string {
	var extra []string
	for _, a := range aud {
		if a != clientID {
			extra = append(extra, a)
		}
	}
	return extra
}

func VerifyIDTokenWithNonce(idToken, expected string, sconfig ServerConfig, cconfig ClientConfig, hc *http.Client) (string, []Verification, error) {
	if idToken == "" {
		if expected == "" {
			return "", nil, nil
		}
		check := nonceVerification(nil, expected)
		check.Received = "(no id_token)"
		check.Result = CheckSkip
		check.Detail = "nonce is bound to the ID Token; no ID Token was returned"
		return "", []Verification{check}, nil
	}

	claims, checks, err := VerifyIDToken(idToken, sconfig, cconfig, hc)
	if claims == nil && err != nil {
		check := nonceVerification(nil, expected)
		check.Received = "(unverified)"
		check.Result = CheckSkip
		check.Detail = "ID Token was not verified"
		return "", append(checks, check), err
	}

	nonceCheck := nonceVerification(claims, expected)
	checks = append(checks, nonceCheck)

	if err != nil {
		return "", checks, err
	}
	if nonceCheck.Result == CheckFail {
		if expected != "" && nonceCheck.Received == "(missing)" {
			return "", checks, ErrIDTokenNonceMissing
		}
		return nonceCheck.Received, checks, fmt.Errorf("sent %q, got %q: %w", expected, nonceCheck.Received, ErrIDTokenNonceMismatch)
	}
	if nonceCheck.Result != CheckPass {
		return "", checks, nil
	}
	return nonceCheck.Received, checks, nil
}

func nonceVerification(claims map[string]interface{}, expected string) Verification {
	check := passCheck("id_token.nonce", oidcCoreSpec, "replay protection")
	got := claimString(claims, "nonce")

	switch {
	case expected == "" && got == "":
		check.Expected = "(not sent)"
		check.Received = "(not present)"
		check.Result = CheckSkip
		check.Detail = "nonce was not sent in the request"
	case expected == "":
		check.Expected = "(not sent)"
		check.Received = got
		check.Result = CheckSkip
		check.Detail = "nonce was not sent in the request"
	case got == "":
		check.Expected = expected
		check.Received = "(missing)"
		check.Result = CheckFail
		check.Detail = "authorization server did not echo nonce in the ID Token"
	case got != expected:
		check.Expected = expected
		check.Received = got
		check.Result = CheckFail
		check.Detail = fmt.Sprintf("sent %q, got %q", expected, got)
	default:
		check.Expected = expected
		check.Received = got
	}

	return check
}

func claimString(claims map[string]interface{}, key string) string {
	if claims == nil {
		return ""
	}
	s, _ := claims[key].(string)
	return s
}

type SignerProvider func() (jose.Signer, interface{}, error)

func JWKSigner(keyPath string, hc *http.Client) SignerProvider {
	return func() (signer jose.Signer, _ interface{}, err error) {
		var key jose.JSONWebKey

		if keyPath == "" {
			return nil, nil, errors.New("no signing key path")
		}

		if key, err = ReadKey(SigningKey, keyPath, hc); err != nil {
			return nil, nil, fmt.Errorf("failed to read signing key from %s: %w", keyPath, err)
		}

		if key.IsPublic() {
			return nil, nil, errors.New("signing key must be private")
		}

		if signer, err = jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(key.Algorithm),
			Key:       key.Key,
		}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": key.KeyID},
		}); err != nil {
			return nil, nil, fmt.Errorf("failed to create a signer: %w", err)
		}

		return signer, key.Key, nil
	}
}

func SecretSigner(secret []byte) SignerProvider {
	return func() (jose.Signer, interface{}, error) {
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       secret,
		}, nil)

		return signer, secret, err
	}
}

type ClaimsProvider func() (map[string]interface{}, error)

func AssertionClaims(serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		var err error

		claims := map[string]interface{}{
			"iss": serverConfig.TokenEndpoint,
			"aud": serverConfig.TokenEndpoint,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"jti": RandomString(20),
		}

		if clientConfig.Assertion == "" {
			clientConfig.Assertion = "{}"
		}

		if err = json.Unmarshal([]byte(clientConfig.Assertion), &claims); err != nil {
			return nil, err
		}

		return claims, nil
	}
}

func RequestObjectClaims(params url.Values, serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		claims := map[string]interface{}{
			"iss": clientConfig.ClientID,
			"aud": clientConfig.IssuerURL,
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"nbf": time.Now().Unix(),
		}

		for key, values := range params {
			if len(values) == 0 {
				continue
			}

			val := values[0]

			if len(val) > 0 && (val[0] == '{' || val[0] == '[') {
				claims[key] = jsontext.Value(val)
			} else {
				claims[key] = val
			}
		}

		return claims, nil
	}
}

func ClientAssertionClaims(serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		return map[string]interface{}{
			"iss": clientConfig.ClientID,
			"sub": clientConfig.ClientID,
			"aud": clientConfig.IssuerURL,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"jti": RandomString(20),
		}, nil
	}
}

func SignJWT(claimsProvider ClaimsProvider, signerProvider SignerProvider) (jwt string, key interface{}, err error) {
	var (
		signer jose.Signer
		claims map[string]interface{}
		jws    *jose.JSONWebSignature
		bs     []byte
	)

	if signer, key, err = signerProvider(); err != nil {
		return "", nil, fmt.Errorf("failed to create signer: %w", err)
	}

	if claims, err = claimsProvider(); err != nil {
		return "", nil, fmt.Errorf("failed to build claims: %w", err)
	}

	if bs, err = json.Marshal(claims); err != nil {
		return "", nil, fmt.Errorf("failed to serialize claims: %w", err)
	}

	if jws, err = signer.Sign(bs); err != nil {
		return "", nil, fmt.Errorf("failed to sign jwt: %w", err)
	}

	if jwt, err = jws.CompactSerialize(); err != nil {
		return "", nil, err
	}

	return jwt, key, nil
}

func PlaintextJWT(claimsProvider ClaimsProvider) (string, string, error) {
	var (
		claims     map[string]interface{}
		claimsJSON []byte
		err        error
	)

	if claims, err = claimsProvider(); err != nil {
		return "", "", fmt.Errorf("failed to build claims: %w", err)
	}

	if claimsJSON, err = json.Marshal(claims); err != nil {
		return "", "", fmt.Errorf("failed to serialize claims: %w", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return header + "." + payload + ".", "none", nil
}
