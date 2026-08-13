package oauth2

import "testing"

func TestErrorStringIncludesDescription(t *testing.T) {
	err := &Error{
		StatusCode:  400,
		ErrorCode:   "invalid_request",
		Description: "audience is required",
	}

	eq(t, err.Error(), "400: invalid_request: audience is required")
}

func TestErrorStringWithoutDescription(t *testing.T) {
	err := &Error{
		StatusCode: 400,
		ErrorCode:  "invalid_request",
	}

	eq(t, err.Error(), "400: invalid_request")
}
