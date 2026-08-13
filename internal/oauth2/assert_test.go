package oauth2

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func isErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
}

func eq(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func notEq(t *testing.T, got, want any) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		t.Fatalf("got equal values %#v", got)
	}
}

func empty(t *testing.T, v any) {
	t.Helper()
	if !isEmptyVal(v) {
		t.Fatalf("got %#v, want empty", v)
	}
}

func notEmpty(t *testing.T, v any) {
	t.Helper()
	if isEmptyVal(v) {
		t.Fatal("expected non-empty value")
	}
}

func isEmptyVal(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String, reflect.Array, reflect.Slice, reflect.Map:
		return rv.Len() == 0
	default:
		return rv.IsZero()
	}
}

func contains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("%q does not contain %q", s, sub)
	}
}

func errorIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got %v, want %v", err, target)
	}
}

func notErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if errors.Is(err, target) {
		t.Fatalf("got %v, did not want %v", err, target)
	}
}
