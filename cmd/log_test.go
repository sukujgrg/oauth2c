package cmd

import (
	"bytes"
	"net/url"
	"os"
	"testing"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/pterm/pterm"
	"github.com/stretchr/testify/require"
)

func TestLogAccessTokenPayload(t *testing.T) {
	t.Run("opaque token", func(t *testing.T) {
		output := captureLogOutput(t)

		LogTokenPayload(oauth2.TokenResponse{AccessToken: "opaque-access-token"})

		require.Contains(t, output.String(), "Access token: (opaque or non-JWT)")
		require.NotContains(t, output.String(), "ERROR")
		require.NotContains(t, output.String(), "compact JWS")
	})

	t.Run("signed JWT", func(t *testing.T) {
		output := captureLogOutput(t)
		token, _, err := oauth2.SignJWT(
			func() (map[string]interface{}, error) {
				return map[string]interface{}{"sub": "user"}, nil
			},
			oauth2.SecretSigner([]byte("test-secret-that-is-long-enough-for-hs256")),
		)
		require.NoError(t, err)

		LogAccessTokenPayload("Access token", token)

		require.Contains(t, output.String(), "Access token:")
		require.Contains(t, output.String(), `"sub"`)
		require.Contains(t, output.String(), `"user"`)
		require.NotContains(t, output.String(), "opaque or non-JWT")
	})
}

func TestLogSubjectTokenAndActorTokenWithOpaqueTokens(t *testing.T) {
	output := captureLogOutput(t)

	LogSubjectTokenAndActorToken(oauth2.Request{Form: url.Values{
		"subject_token": {"opaque-subject-token"},
		"actor_token":   {"opaque-actor-token"},
	}})

	require.Contains(t, output.String(), "Subject token: (opaque or non-JWT)")
	require.Contains(t, output.String(), "Actor token: (opaque or non-JWT)")
	require.NotContains(t, output.String(), "ERROR")
	require.NotContains(t, output.String(), "compact JWS")
}

func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()

	output := &bytes.Buffer{}
	pterm.SetDefaultOutput(output)
	pterm.DisableStyling()
	t.Cleanup(func() {
		pterm.SetDefaultOutput(os.Stderr)
		pterm.EnableStyling()
	})

	return output
}
