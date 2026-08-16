package main

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/sukujgrg/oauth2c/cmd"
)

var (
	version = "master"
	commit  = "none"
	date    = "unknown"
)

func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cmd.LogError(errors.New("Interrupted"))
		os.Exit(1)
	}()
}

func main() {
	version, commit, date = cmd.ResolveBuildIdentity(version, commit, date)
	if err := cmd.NewOAuth2Cmd(version, commit, date).Execute(); err != nil {
		cmd.LogError(err)
		os.Exit(1)
	}
}
