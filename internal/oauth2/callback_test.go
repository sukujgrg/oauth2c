package oauth2

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestWaitForCallbackRejectsMissingState(t *testing.T) {
	_, err := WaitForCallback(ClientConfig{
		RedirectURL: "http://127.0.0.1:9876/callback",
	}, ServerConfig{}, http.DefaultClient, "")
	isErr(t, err)
	contains(t, err.Error(), "missing expected state")
}

func TestWaitForCallbackRejectsStateMismatchWithoutShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	noErr(t, err)
	addr := ln.Addr().String()
	noErr(t, ln.Close())

	expected := "csrf-state-value"
	redirect := "http://" + addr + "/callback"
	cfg := ClientConfig{
		RedirectURL:    redirect,
		CallbackAddr:   addr,
		BrowserTimeout: 5 * time.Second,
	}

	type outcome struct {
		req Request
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		req, err := WaitForCallback(cfg, ServerConfig{}, http.DefaultClient, expected)
		done <- outcome{req, err}
	}()

	waitCallbackListening(t, redirect)

	resp, err := http.Get(redirect + "?code=injected&state=attacker")
	noErr(t, err)
	eq(t, resp.StatusCode, http.StatusBadRequest)
	body, err := io.ReadAll(resp.Body)
	noErr(t, err)
	noErr(t, resp.Body.Close())
	contains(t, string(body), "invalid state")

	select {
	case got := <-done:
		t.Fatalf("callback server shut down after state mismatch: %#v, %v", got.req, got.err)
	default:
	}

	resp, err = http.Get(redirect + "?code=&state=")
	noErr(t, err)
	eq(t, resp.StatusCode, http.StatusBadRequest)
	noErr(t, resp.Body.Close())

	resp, err = http.Get(redirect + "?code=good&state=" + url.QueryEscape(expected))
	noErr(t, err)
	eq(t, resp.StatusCode, http.StatusOK)
	noErr(t, resp.Body.Close())

	got := <-done
	noErr(t, got.err)
	eq(t, got.req.Get("code"), "good")
}

func waitCallbackListening(t *testing.T, rawURL string) {
	t.Helper()
	client := &http.Client{Timeout: 50 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(rawURL)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			noErr(t, resp.Body.Close())
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("callback server did not start")
}
