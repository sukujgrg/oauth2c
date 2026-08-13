package oauth2

import (
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

type EncrypterProvider func() (jose.Encrypter, interface{}, error)

func JWEEncrypter(keyPath string, hc *http.Client) EncrypterProvider {
	return func() (encrypter jose.Encrypter, _ interface{}, err error) {
		var key jose.JSONWebKey

		if keyPath == "" {
			return nil, nil, fmt.Errorf("no encryption key path")
		}

		if key, err = ReadKey(EncryptionKey, keyPath, hc); err != nil {
			return nil, nil, fmt.Errorf("failed to read encryption key from %s: %w", keyPath, err)
		}

		if encrypter, err = jose.NewEncrypter(
			jose.A256GCM,
			jose.Recipient{
				Algorithm: jose.KeyAlgorithm(key.Algorithm),
				Key:       key.Key,
			},
			(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
		); err != nil {
			return nil, nil, fmt.Errorf("failed to create an encrypter: %w", err)
		}

		return encrypter, key.Key, nil
	}
}

func EncryptJWT(token string, encrypterProvider EncrypterProvider) (nestedJWT string, key interface{}, err error) {
	var (
		encrypter jose.Encrypter
		jwe       *jose.JSONWebEncryption
	)

	if encrypter, key, err = encrypterProvider(); err != nil {
		return "", nil, err
	}

	if jwe, err = encrypter.Encrypt([]byte(token)); err != nil {
		return "", nil, err
	}

	if nestedJWT, err = jwe.CompactSerialize(); err != nil {
		return "", nil, err
	}

	return nestedJWT, key, nil
}
