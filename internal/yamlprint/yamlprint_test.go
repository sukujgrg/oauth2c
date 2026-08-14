package yamlprint

import (
	"bytes"
	"strings"
	"testing"
)

func TestMarshalStruct(t *testing.T) {
	got, err := New().Marshal(struct {
		Spec    string `yaml:"spec"`
		Purpose string `yaml:"purpose"`
		Empty   string `yaml:"empty,omitempty"`
	}{
		Spec:    "RFC 6749",
		Purpose: "CSRF protection",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := strings.Join([]string{
		"spec: RFC 6749",
		"purpose: CSRF protection",
		"",
	}, "\n")
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWrite(t *testing.T) {
	var buf bytes.Buffer
	err := New().Write(&buf, map[string]string{"token_type": "Bearer"})
	if err != nil {
		t.Fatal(err)
	}

	if buf.String() != "token_type: Bearer\n" {
		t.Fatalf("got %q", buf.String())
	}
}

func TestMarshalWholeFloatsAsInts(t *testing.T) {
	got, err := New().Marshal(map[string]any{
		"exp": float64(1786775334),
		"iat": 1.786739334e+09,
		"nbf": 1.5,
	})
	if err != nil {
		t.Fatal(err)
	}

	text := string(got)
	if !strings.Contains(text, "exp: 1786775334") {
		t.Fatalf("got %q", text)
	}
	if !strings.Contains(text, "iat: 1786739334") {
		t.Fatalf("got %q", text)
	}
	if !strings.Contains(text, "nbf: 1.5") {
		t.Fatalf("got %q", text)
	}
	if strings.Contains(text, "e+09") || strings.Contains(text, "e+9") {
		t.Fatalf("scientific notation leaked: %q", text)
	}
}

func TestMarshalDoesNotMutateInput(t *testing.T) {
	in := map[string]any{"exp": float64(1786775334)}
	if _, err := New().Marshal(in); err != nil {
		t.Fatal(err)
	}
	if _, ok := in["exp"].(float64); !ok {
		t.Fatalf("input mutated: %#v", in["exp"])
	}
}

func TestMarshalNestedClaimFloats(t *testing.T) {
	got, err := New().Marshal(struct {
		JWS    string         `yaml:"jws"`
		Claims map[string]any `yaml:",inline"`
	}{
		JWS:    "JWT-HS256",
		Claims: map[string]any{"exp": float64(1786775334)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "exp: 1786775334") {
		t.Fatalf("got %q", got)
	}
}

func TestFromJSON(t *testing.T) {
	n, err := FromJSON(struct {
		TokenType string `json:"token_type"`
		Hidden    string `json:"-"`
	}{
		TokenType: "Bearer",
		Hidden:    "nope",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := New().Marshal(n)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(got), "token_type: Bearer") {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(string(got), "Hidden") || strings.Contains(string(got), "nope") {
		t.Fatalf("json name conversion leaked Go fields: %q", got)
	}
}
