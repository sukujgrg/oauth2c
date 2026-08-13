package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudentity/oauth2c/cmd"
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
		fmt.Fprintln(os.Stderr, "Interrupted")
		os.Exit(1)
	}()
}

func main() {
	if err := cmd.NewOAuth2Cmd(version, commit, date).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
