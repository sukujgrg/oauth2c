package oauth2

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

func VerifyIDToken(idToken string, sconfig ServerConfig, cconfig ClientConfig, hc *http.Client) (map[string]interface{}, error) {
	token, err := jwt.ParseSigned(idToken, JOSESignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id token: %w", err)
	}

	var (
		keys       jose.JSONWebKeySet
		registered jwt.Claims
		claims     = map[string]interface{}{}
		hmacKey    []byte
	)

	if sconfig.JWKsURI != "" {
		if keys, err = ReadKeySet(sconfig.JWKsURI, hc); err != nil {
			return nil, fmt.Errorf("failed to verify id token signature: %w", err)
		}
	}

	if cconfig.ClientSecret != "" {
		hmacKey = []byte(cconfig.ClientSecret)
	}

	if err = verifyIDTokenSignature(token, keys, hmacKey, &registered, &claims); err != nil {
		return nil, err
	}

	if err = validateIDTokenClaims(registered, sconfig, cconfig); err != nil {
		return nil, err
	}

	return claims, nil
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

func validateIDTokenClaims(registered jwt.Claims, sconfig ServerConfig, cconfig ClientConfig) error {
	if registered.Issuer == "" {
		return errors.New("id token iss claim is missing")
	}
	if len(registered.Audience) == 0 {
		return errors.New("id token aud claim is missing")
	}
	if registered.Expiry == nil {
		return errors.New("id token exp claim is missing")
	}
	if registered.IssuedAt == nil {
		return errors.New("id token iat claim is missing")
	}

	issuer := sconfig.Issuer
	if issuer == "" {
		issuer = cconfig.IssuerURL
	}

	expected := jwt.Expected{
		Time: time.Now(),
	}
	if issuer != "" {
		expected.Issuer = issuer
	}
	if cconfig.ClientID != "" {
		expected.AnyAudience = jwt.Audience{cconfig.ClientID}
	}

	if err := registered.Validate(expected); err != nil {
		return fmt.Errorf("id token claims are invalid: %w", err)
	}

	return nil
}

func CheckIDTokenNonce(idToken, expected string, sconfig ServerConfig, cconfig ClientConfig, hc *http.Client) (string, error) {
	if expected == "" || idToken == "" {
		return "", nil
	}

	claims, err := VerifyIDToken(idToken, sconfig, cconfig, hc)
	if err != nil {
		return "", err
	}

	got, _ := claims["nonce"].(string)
	if got == "" {
		return "", ErrIDTokenNonceMissing
	}

	if got != expected {
		return got, fmt.Errorf("sent %q, got %q: %w", expected, got, ErrIDTokenNonceMismatch)
	}

	return got, nil
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
