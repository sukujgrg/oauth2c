package cmd

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"strings"
	"testing"
)

type CommandTestCase struct {
	title string
	args  []string
	deps  map[string]CommandDependency
	err   error
}

type CommandDependency struct {
	args  []string
	field string
}

func (tc *CommandTestCase) Test() func(*testing.T) {
	return func(t *testing.T) {
		deps := tc.GetDeps(t)

		args := append([]string(nil), tc.args...)
		for i, arg := range args {
			if strings.HasPrefix(arg, "$") {
				args[i] = deps[arg[1:]]
			}
		}

		cmd := NewOAuth2Cmd("master", "none", "unknown")
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		err := cmd.Execute()

		if tc.err == nil {
			noErr(t, err)
		} else {
			isErr(t, err)
			eq(t, err.Error(), tc.err.Error())
		}
	}
}

func (tc *CommandTestCase) GetDeps(t *testing.T) map[string]string {
	t.Helper()
	deps := make(map[string]string)

	for name, dep := range tc.deps {
		output := bytes.Buffer{}
		result := map[string]interface{}{}

		args := append([]string(nil), dep.args...)
		cmd := NewOAuth2Cmd("master", "none", "unknown")
		cmd.SetArgs(args)
		cmd.SetOut(&output)
		err := cmd.Execute()

		noErr(t, err)

		err = json.Unmarshal(output.Bytes(), &result)
		noErr(t, err)

		v, ok := result[dep.field].(string)
		isTrue(t, ok)
		notEmpty(t, v)

		deps[name] = v
	}

	return deps
}

func TestRejectEmptyFlags(t *testing.T) {
	t.Run("client-id empty", func(t *testing.T) {
		cmd := NewOAuth2Cmd("master", "none", "unknown")
		noErr(t, cmd.ParseFlags([]string{"--client-id", ""}))
		err := rejectEmptyFlags(cmd.Command)
		isErr(t, err)
		contains(t, err.Error(), "--client-id is empty")
	})

	t.Run("client-id whitespace", func(t *testing.T) {
		cmd := NewOAuth2Cmd("master", "none", "unknown")
		noErr(t, cmd.ParseFlags([]string{"--client-id", "   "}))
		err := rejectEmptyFlags(cmd.Command)
		isErr(t, err)
		contains(t, err.Error(), "--client-id is empty")
	})

	t.Run("omitted client-id is ok", func(t *testing.T) {
		cmd := NewOAuth2Cmd("master", "none", "unknown")
		noErr(t, cmd.ParseFlags([]string{"--grant-type", "client_credentials"}))
		noErr(t, rejectEmptyFlags(cmd.Command))
	})

	t.Run("audience empty value", func(t *testing.T) {
		cmd := NewOAuth2Cmd("master", "none", "unknown")
		noErr(t, cmd.ParseFlags([]string{"--audience", ""}))
		err := rejectEmptyFlags(cmd.Command)
		isErr(t, err)
		contains(t, err.Error(), "--audience is empty")
	})

	t.Run("scopes mixed empty", func(t *testing.T) {
		cmd := NewOAuth2Cmd("master", "none", "unknown")
		noErr(t, cmd.ParseFlags([]string{"--scopes", "openid,"}))
		err := rejectEmptyFlags(cmd.Command)
		isErr(t, err)
		contains(t, err.Error(), "--scopes has an empty value")
	})

	t.Run("populated flags pass", func(t *testing.T) {
		cmd := NewOAuth2Cmd("master", "none", "unknown")
		noErr(t, cmd.ParseFlags([]string{
			"--client-id", "client",
			"--client-secret", "secret",
			"--audience", "https://api.example",
		}))
		noErr(t, rejectEmptyFlags(cmd.Command))
	})
}

func TestRedirectURIAlias(t *testing.T) {
	cmd := NewOAuth2Cmd("master", "none", "unknown")
	noErr(t, cmd.ParseFlags([]string{"--redirect-uri", "http://127.0.0.1:8400/oauth/callback"}))
	eq(t, cmd.Flag("redirect-url").Value.String(), "http://127.0.0.1:8400/oauth/callback")
	eq(t, cmd.Flag("redirect-uri").Value.String(), "http://127.0.0.1:8400/oauth/callback")
}

func TestCobraErrorsStayOffStderr(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown flag", args: []string{"--not-a-real-flag"}, want: "unknown flag"},
		{name: "missing issuer", args: []string{"--grant-type", "client_credentials"}, want: "accepts 1 arg(s)"},
		{name: "version unknown flag", args: []string{"version", "--not-a-real-flag"}, want: "unknown flag"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stderr := &bytes.Buffer{}
			cmd := NewOAuth2Cmd("master", "none", "unknown")
			cmd.SetArgs(tc.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(stderr)
			err := cmd.Execute()
			isErr(t, err)
			contains(t, err.Error(), tc.want)
			eq(t, stderr.String(), "")
		})
	}
}
