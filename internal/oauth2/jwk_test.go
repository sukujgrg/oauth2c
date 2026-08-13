package oauth2

import (
	"net/http"
	"testing"
)

func TestReadKey(t *testing.T) {
	key, err := ReadKey(SigningKey, "../../data/rsa/key.json", http.DefaultClient)
	noErr(t, err)
	if key.Key == nil {
		t.Fatal("expected signing key")
	}
}
