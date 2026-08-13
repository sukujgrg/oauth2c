package oauth2

import "testing"

func TestRandomString(t *testing.T) {
	notEq(t, RandomString(10), RandomString(10))
}
