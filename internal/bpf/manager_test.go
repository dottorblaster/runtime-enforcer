//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
)

func TestLearning(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         learningChannel,
		shouldFindEvent: true,
	}))
}

func TestMonitorProtectMode(t *testing.T) {
	runner, err := newCgroupRunner(t)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	//////////////////////
	// Populate the policy map
	//////////////////////
	mockPolicyID := uint64(42)

	// populate policy values
	// only `pol_str_maps_0` will be popoulated here, all the other maps won't be created.
	err = runner.manager.GetPolicyValuesUpdateFunc()(mockPolicyID, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy values")

	// populate policy mode to monitor
	err = runner.manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Monitor, UpdateMode)
	require.NoError(t, err, "Failed to set policy mode")

	// populate cgroup to track
	err = runner.manager.GetCgroupPolicyUpdateFunc()(mockPolicyID, []uint64{runner.cgInfo.id}, AddPolicyToCgroups)
	require.NoError(t, err, "Failed to add policy to cgroup")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	t.Log("Trying allowed binary in monitor mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}))

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in monitor mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/who",
		channel:         monitoringChannel,
		shouldFindEvent: true,
	}))

	//////////////////////
	// Try a binary that is not allowed and that is not in `pol_str_maps_0`
	//////////////////////
	t.Log("Write temp binary")
	tmpPath := filepath.Join(t.TempDir(), strings.Repeat("A", 128))
	content := []byte("#!/bin/bash\n/usr/bin/true\n")
	// we want this to be executable
	err = os.WriteFile(tmpPath, content, 0755)
	require.NoError(t, err, "Failed to write temporary file")
	defer os.Remove(tmpPath)

	// we didn't create a map for a path with this len so we expect this to be reported as not allowed
	t.Log("Trying binary with path len > 128 in monitor mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         tmpPath,
		channel:         monitoringChannel,
		shouldFindEvent: true,
	}))

	//////////////////////
	// Switch to enforcing mode
	//////////////////////
	t.Log("Switching to enforcing mode")
	err = runner.manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Protect, UpdateMode)
	require.NoError(t, err, "Failed to set policy to protect")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	// Should behave like the monitor mode
	t.Log("Trying allowed binary in enforcing mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}))

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in enforcing mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         "/usr/bin/who",
		channel:         monitoringChannel,
		shouldFindEvent: true,
		shouldEPERM:     true,
	}))

	//////////////////////
	// Try a binary that is not allowed and that is not in `pol_str_maps_0`
	//////////////////////
	t.Log("Trying binary with path len > 128 in enforcing mode")
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command:         tmpPath,
		channel:         monitoringChannel,
		shouldEPERM:     true,
		shouldFindEvent: true,
	}))
}

func TestMultiplePolicies(t *testing.T) {
	manager, cleanup, err := waitRunningManager(t)
	require.NoError(t, err, "Failed to start manager")
	defer cleanup()

	mockPolicyID1 := uint64(42)
	err = manager.GetPolicyValuesUpdateFunc()(mockPolicyID1, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 1 values")

	// We try to create 2 policies to check if `max_entries`
	// for string maps is really greater than 1.
	mockPolicyID2 := uint64(43)
	err = manager.GetPolicyValuesUpdateFunc()(mockPolicyID2, []string{"/usr/bin/who"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 2 values")
}
