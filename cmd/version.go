package cmd

import (
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

func NewVersionCmd(version, commit, date string) *cobra.Command {
	return &cobra.Command{
		Use:           "version",
		Short:         "Display version",
		SilenceUsage:  true,
		SilenceErrors: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("oauth2c version %s (commit %s, built at %s)\n", version, commit, date)
		},
	}
}

// ResolveBuildIdentity fills in GoReleaser-unstamped builds (`go install`,
// local `go build`) from module build info. Stamped release values win.
func ResolveBuildIdentity(version, commit, date string) (string, string, string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version, commit, date
	}
	return applyBuildInfo(version, commit, date, info)
}

func applyBuildInfo(version, commit, date string, info *debug.BuildInfo) (string, string, string) {
	if info == nil {
		return version, commit, date
	}
	if version == "" || version == "master" {
		if v := strings.TrimPrefix(info.Main.Version, "v"); v != "" {
			version = v
		}
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if (commit == "" || commit == "none") && s.Value != "" {
				commit = s.Value
				if len(commit) > 7 {
					commit = commit[:7]
				}
			}
		case "vcs.time":
			if (date == "" || date == "unknown") && s.Value != "" {
				date = s.Value
			}
		}
	}
	return version, commit, date
}
