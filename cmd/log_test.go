package cmd

import (
	"bytes"
	"net/url"
	"testing"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func TestLogAccessTokenPayload(t *testing.T) {
	t.Run("opaque token", func(t *testing.T) {
		output := captureLogOutput(t)

		LogTokenPayload(oauth2.TokenResponse{AccessToken: "opaque-access-token"})

		contains(t, output.String(), "Access token: (opaque or non-JWT)")
		notContains(t, output.String(), "ERROR")
		notContains(t, output.String(), "compact JWS")
	})

	t.Run("signed JWT", func(t *testing.T) {
		output := captureLogOutput(t)
		token, _, err := oauth2.SignJWT(
			func() (map[string]interface{}, error) {
				return map[string]interface{}{"sub": "user"}, nil
			},
			oauth2.SecretSigner([]byte("test-secret-that-is-long-enough-for-hs256")),
		)
		noErr(t, err)

		LogAccessTokenPayload("Access token", token)

		contains(t, output.String(), "Access token:")
		contains(t, output.String(), `"sub"`)
		contains(t, output.String(), `"user"`)
		notContains(t, output.String(), "opaque or non-JWT")
	})
}

func TestLogSubjectTokenAndActorTokenWithOpaqueTokens(t *testing.T) {
	output := captureLogOutput(t)

	LogSubjectTokenAndActorToken(oauth2.Request{Form: url.Values{
		"subject_token": {"opaque-subject-token"},
		"actor_token":   {"opaque-actor-token"},
	}})

	contains(t, output.String(), "Subject token: (opaque or non-JWT)")
	contains(t, output.String(), "Actor token: (opaque or non-JWT)")
	notContains(t, output.String(), "ERROR")
	notContains(t, output.String(), "compact JWS")
}

func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()

	output := &bytes.Buffer{}
	prev := logOut
	logOut = output
	t.Cleanup(func() {
		logOut = prev
	})

	return output
}
