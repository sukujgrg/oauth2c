package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Live Auth0 tests read these variables from the process environment or
// from .env.auth0 (written by scripts/setup-auth0.sh). They skip when the
// file and env are absent so CI without a tenant still passes.
type auth0Env struct {
	Issuer     string
	Audience   string
	Scope      string
	WebID      string
	WebSecret  string
	PostID     string
	PostSecret string
	Username   string
	Password   string
}

var loadDotEnvOnce = sync.OnceFunc(func() {
	for _, path := range auth0EnvPaths() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for key, val := range parseDotEnv(data) {
			if os.Getenv(key) == "" {
				_ = os.Setenv(key, val)
			}
		}
		return
	}
})

func auth0EnvPaths() []string {
	var paths []string
	if p := os.Getenv("OAUTH2C_ENV_FILE"); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths, ".env.auth0", filepath.Join("..", ".env.auth0"))
	return paths
}

func parseDotEnv(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if key != "" {
			out[key] = val
		}
	}
	return out
}

func requireAuth0(t *testing.T) auth0Env {
	t.Helper()
	loadDotEnvOnce()

	env := auth0Env{
		Issuer:     strings.TrimRight(os.Getenv("OAUTH2C_ISSUER"), "/"),
		Audience:   os.Getenv("OAUTH2C_AUDIENCE"),
		Scope:      os.Getenv("OAUTH2C_SCOPE"),
		WebID:      os.Getenv("OAUTH2C_WEB_CLIENT_ID"),
		WebSecret:  os.Getenv("OAUTH2C_WEB_CLIENT_SECRET"),
		PostID:     os.Getenv("OAUTH2C_POST_CLIENT_ID"),
		PostSecret: os.Getenv("OAUTH2C_POST_CLIENT_SECRET"),
		Username:   os.Getenv("OAUTH2C_USERNAME"),
		Password:   os.Getenv("OAUTH2C_PASSWORD"),
	}

	missing := make([]string, 0, 9)
	for _, pair := range []struct {
		name, val string
	}{
		{"OAUTH2C_ISSUER", env.Issuer},
		{"OAUTH2C_AUDIENCE", env.Audience},
		{"OAUTH2C_SCOPE", env.Scope},
		{"OAUTH2C_WEB_CLIENT_ID", env.WebID},
		{"OAUTH2C_WEB_CLIENT_SECRET", env.WebSecret},
		{"OAUTH2C_POST_CLIENT_ID", env.PostID},
		{"OAUTH2C_POST_CLIENT_SECRET", env.PostSecret},
		{"OAUTH2C_USERNAME", env.Username},
		{"OAUTH2C_PASSWORD", env.Password},
	} {
		if pair.val == "" {
			missing = append(missing, pair.name)
		}
	}
	if len(missing) > 0 {
		t.Skip("Auth0 live tests need .env.auth0 from scripts/setup-auth0.sh (missing " + strings.Join(missing, ", ") + ")")
	}
	return env
}

func TestParseDotEnv(t *testing.T) {
	got := parseDotEnv([]byte(`
# comment
OAUTH2C_ISSUER=https://example.us.auth0.com
OAUTH2C_AUDIENCE="https://oauth2c.local"
OAUTH2C_SCOPE='demo:read'
empty=
not_a_pair
`))
	eq(t, got["OAUTH2C_ISSUER"], "https://example.us.auth0.com")
	eq(t, got["OAUTH2C_AUDIENCE"], "https://oauth2c.local")
	eq(t, got["OAUTH2C_SCOPE"], "demo:read")
	eq(t, got["empty"], "")
	if _, ok := got["not_a_pair"]; ok {
		t.Fatal("expected unparseable line to be ignored")
	}
}
