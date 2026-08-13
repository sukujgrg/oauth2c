package oauth2

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

type KeyUse string

const (
	SigningKey    KeyUse = "sig"
	EncryptionKey KeyUse = "enc"
)

func ReadKeySet(location string, hc *http.Client) (jose.JSONWebKeySet, error) {
	var (
		keys jose.JSONWebKeySet
		bs   []byte
		resp *http.Response
		err  error
	)

	if strings.HasPrefix(location, "http") {
		if resp, err = hc.Get(location); err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("failed to call: %s: %w", location, err)
		}
		defer resp.Body.Close()

		if bs, err = io.ReadAll(resp.Body); err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("failed to read response body from: %s: %w", location, err)
		}

		if resp.StatusCode != 200 {
			return jose.JSONWebKeySet{}, fmt.Errorf("received unexpected status code: %d, body: %s", resp.StatusCode, string(bs))
		}
	} else {
		if bs, err = os.ReadFile(location); err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("failed to read file: %s: %w", location, err)
		}
	}

	if err = json.Unmarshal(bs, &keys); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("failed to parse jwks keys: %s: %w", location, err)
	}

	if len(keys.Keys) == 0 {
		return jose.JSONWebKeySet{}, fmt.Errorf("keys are empty")
	}

	return keys, nil
}

func ReadKey(use KeyUse, location string, hc *http.Client) (jose.JSONWebKey, error) {
	keys, err := ReadKeySet(location, hc)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	for _, key := range keys.Keys {
		if key.Use == string(use) {
			return key, nil
		}
	}

	return jose.JSONWebKey{}, fmt.Errorf("could not find %s key", use)
}
