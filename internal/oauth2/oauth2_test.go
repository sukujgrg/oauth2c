package oauth2

import (
	"encoding/json/v2"
	"errors"
	"testing"
)

func TestTokenResponseExtraFields(t *testing.T) {
	body := []byte(`{
		"access_token": "token",
		"expires_in": 3600,
		"token_type": "Bearer",
		"email": "me@email.com",
		"environment_id": "envid-token-here",
		"legal_entity_name": "oauth environment provider"
	}`)

	var resp TokenResponse
	noErr(t, json.Unmarshal(body, &resp))

	eq(t, resp.AccessToken, "token")
	eq(t, resp.ExpiresIn, FlexibleInt64(3600))
	eq(t, resp.TokenType, "Bearer")

	out, err := json.Marshal(resp)
	noErr(t, err)

	var roundTrip map[string]any
	noErr(t, json.Unmarshal(out, &roundTrip))

	eq(t, roundTrip["access_token"], "token")
	eq(t, roundTrip["token_type"], "Bearer")
	eq(t, roundTrip["email"], "me@email.com")
	eq(t, roundTrip["environment_id"], "envid-token-here")
	eq(t, roundTrip["legal_entity_name"], "oauth environment provider")
	if _, ok := roundTrip["raw"]; ok {
		t.Fatal("round trip should not contain raw")
	}
}

func TestTokenResponseNoExtraFields(t *testing.T) {
	body := []byte(`{"access_token": "token", "expires_in": 3600, "token_type": "Bearer"}`)

	var resp TokenResponse
	noErr(t, json.Unmarshal(body, &resp))

	out, err := json.Marshal(resp)
	noErr(t, err)

	var roundTrip map[string]any
	noErr(t, json.Unmarshal(out, &roundTrip))

	eq(t, roundTrip["access_token"], "token")
	eq(t, roundTrip["token_type"], "Bearer")
	if len(roundTrip) != 3 {
		t.Fatalf("len = %d, want 3", len(roundTrip))
	}
}

func TestTokenResponseTypedFieldsWinOnConflict(t *testing.T) {
	body := []byte(`{"access_token": "from-server", "expires_in": "3600"}`)

	var resp TokenResponse
	noErr(t, json.Unmarshal(body, &resp))

	resp.AccessToken = "overridden"

	out, err := json.Marshal(resp)
	noErr(t, err)

	var roundTrip map[string]any
	noErr(t, json.Unmarshal(out, &roundTrip))

	eq(t, roundTrip["access_token"], "overridden")
	switch v := roundTrip["expires_in"].(type) {
	case float64:
		if int64(v) != 3600 {
			t.Fatalf("expires_in = %v, want 3600", v)
		}
	case int64:
		if v != 3600 {
			t.Fatalf("expires_in = %v, want 3600", v)
		}
	default:
		t.Fatalf("expires_in type %T = %#v, want 3600", v, v)
	}
}

func TestUnmarshalExpires(t *testing.T) {
	tests := map[string]struct {
		bytes         []byte
		expectedValue FlexibleInt64
		expectedErr   error
	}{
		"number": {
			bytes:         []byte(`{"expires_in": 3600}`),
			expectedValue: 3600,
		},
		"number string": {
			bytes:         []byte(`{"expires_in": "3600"}`),
			expectedValue: 3600,
		},
		"null": {
			bytes:         []byte(`{"expires_in": null}`),
			expectedValue: 0,
		},
		"other string": {
			bytes:         []byte(`{"expires_in": "foo"}`),
			expectedValue: 0,
			expectedErr:   errors.New("invalid syntax"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			tokenResponse := TokenResponse{}
			err := json.Unmarshal(test.bytes, &tokenResponse)
			if test.expectedErr != nil {
				isErr(t, err)
				contains(t, err.Error(), test.expectedErr.Error())
			} else {
				noErr(t, err)
				eq(t, tokenResponse.ExpiresIn, test.expectedValue)
			}
		})
	}
}
