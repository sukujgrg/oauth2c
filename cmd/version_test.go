package cmd

import (
	"runtime/debug"
	"testing"
)

func TestApplyBuildInfo(t *testing.T) {
	t.Run("go install v1 is not master", func(t *testing.T) {
		v, _, _ := applyBuildInfo("master", "none", "unknown", &debug.BuildInfo{
			Main: debug.Module{Version: "v1.0.0"},
		})
		eq(t, v, "1.0.0")
	})

	t.Run("go install v2", func(t *testing.T) {
		v, _, _ := applyBuildInfo("master", "none", "unknown", &debug.BuildInfo{
			Main: debug.Module{Version: "v2.0.0"},
		})
		eq(t, v, "2.0.0")
	})

	t.Run("stamped release wins", func(t *testing.T) {
		v, c, d := applyBuildInfo("2.0.0", "abc1234", "stamp", &debug.BuildInfo{
			Main: debug.Module{Version: "v1.0.0"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "ffffffffffffffff"},
				{Key: "vcs.time", Value: "other"},
			},
		})
		eq(t, v, "2.0.0")
		eq(t, c, "abc1234")
		eq(t, d, "stamp")
	})

	t.Run("local devel", func(t *testing.T) {
		v, c, _ := applyBuildInfo("master", "none", "unknown", &debug.BuildInfo{
			Main: debug.Module{Version: "(devel)"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abcdef1234567890"},
			},
		})
		eq(t, v, "(devel)")
		eq(t, c, "abcdef1")
	})
}
