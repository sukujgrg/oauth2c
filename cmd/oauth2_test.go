package cmd

import (
	"bytes"
	"encoding/json/v2"
	"strings"
	"testing"
)

const (
	IssuerURL = "https://oauth2c.us.authz.cloudentity.io/oauth2c/demo"

	ClientCredentialsScopes = "introspect_tokens,revoke_tokens"

	TLSCertURL    = "../data/cert.pem"
	TLSKeyURL     = "../data/key.pem"
	SigningKeyURL = "../data/rsa/key.json"
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

		for i, arg := range tc.args {
			if strings.HasPrefix(arg, "$") {
				tc.args[i] = deps[arg[1:]]
			}
		}

		cmd := NewOAuth2Cmd("master", "none", "unknown")
		cmd.SetArgs(tc.args)
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
	deps := make(map[string]string)

	for name, dep := range tc.deps {
		output := bytes.Buffer{}
		result := map[string]interface{}{}

		cmd := NewOAuth2Cmd("master", "none", "unknown")
		cmd.SetArgs(dep.args)
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
