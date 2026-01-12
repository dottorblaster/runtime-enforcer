//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/neuvector/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type cgroupInfo struct {
	path string
	fd   int
	id   uint64
}

func (c cgroupInfo) Close() {
	if c.fd > 0 {
		syscall.Close(c.fd)
	}
	if c.path != "" {
		// Cgroups can only be removed if they are empty (no processes inside).
		_ = os.Remove(c.path)
	}
}

func (c cgroupInfo) RunInCgroup(command string, args []string) error {
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    c.fd,
	}
	return cmd.Run()
}

func createTestCgroup() (cgroupInfo, error) {
	const cgroupRoot = "/sys/fs/cgroup"
	const cgroupName = "my-random-xyz-test-cgroup"
	cgroupPath := filepath.Join(cgroupRoot, cgroupName)

	var err error
	cgInfo := cgroupInfo{}
	defer func() {
		if err != nil {
			cgInfo.Close()
		}
	}()

	err = os.Mkdir(cgroupPath, 0755)
	if err != nil {
		return cgInfo, fmt.Errorf("error creating cgroup: %w", err)
	}
	cgInfo.path = cgroupPath

	fd, err := syscall.Open(cgInfo.path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return cgInfo, fmt.Errorf("error opening cgroup path: %w", err)
	}
	cgInfo.fd = fd

	cgroupID, err := cgroups.GetCgroupIDFromPath(cgInfo.path)
	if err != nil {
		return cgInfo, fmt.Errorf("error getting cgroup ID from path: %w", err)
	}
	cgInfo.id = cgroupID

	return cgInfo, nil
}

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	// use the formatted output to avoid the new line
	w.t.Logf("%s", string(p))
	return len(p), nil
}

func newTestLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(&testLogWriter{t: t}, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With("component", "bpftest")
}

type ChannelType int

const (
	learningChannel ChannelType = iota
	monitoringChannel
)

func (c ChannelType) String() string {
	switch c {
	case learningChannel:
		return "learning"
	case monitoringChannel:
		return "monitoring"
	default:
		return "unknown"
	}
}

type runCommandArgs struct {
	manager         *Manager
	cgInfo          *cgroupInfo
	command         string
	channel         ChannelType
	shouldEPERM     bool
	shouldFindEvent bool
}

func runAndFindCommand(args *runCommandArgs) error {
	err := args.cgInfo.RunInCgroup(args.command, []string{})
	if args.shouldEPERM {
		if err == nil || !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("expected EPERM error, got: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to run %s in cgroup: %w", args.command, err)
	}

	// Get the event
	err = args.manager.findEventInChannel(args.channel, args.cgInfo.id, args.command)
	if args.shouldFindEvent {
		if err != nil {
			return fmt.Errorf(
				"failed to find (command: %s, cgroup: %d) in channel %s: %w",
				args.command,
				args.cgInfo.id,
				args.channel,
				err,
			)
		}
	} else if err == nil {
		return fmt.Errorf("Did not expect to find (command: %s, cgroup: %d)", args.command, args.cgInfo.id)
	}
	return nil
}

func (m *Manager) findEventInChannel(ty ChannelType, cgID uint64, command string) error {
	// We chose the channel to extract events from based on the learning flag
	var channel <-chan ProcessEvent
	switch ty {
	case learningChannel:
		channel = m.GetLearningChannel()
	case monitoringChannel:
		channel = m.GetMonitoringChannel()
	default:
		panic("unhandled channel type")
	}

	for {
		select {
		case event := <-channel:
			m.logger.Info("Received event", "event", event)
			if event.CgroupID == cgID &&
				event.CgTrackerID == 0 &&
				event.ExePath == command {
				m.logger.Info("Found event", "event", event)
				return nil
			}
		// this timer is recreated on each loop iteration
		// so if we don't receive events for 1 second we time out
		case <-time.After(1 * time.Second):
			return errors.New("timeout waiting for event")
		}
	}
}

func startManager(t *testing.T) (*Manager, func()) {
	// We always enable learning in tests for now so that we can wait for the first event to come
	// and understand that BPF programs are loaded and running
	enableLearning := true
	manager, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch)
	require.NoError(t, err, "Failed to create BPF manager")
	require.NotNil(t, manager, "BPF manager is nil")

	ctx, cancel := context.WithCancel(t.Context())
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return manager.Start(ctx)
	})

	cleanup := func() {
		cancel()
		require.NoError(t, g.Wait(), "Failed to stop BPF manager")
	}
	return manager, cleanup
}

func checkManagerIsStarted(m *Manager) error {
	timeoutChan := time.After(5 * time.Second)
	for {
		select {
		case <-m.GetLearningChannel():
			return nil
		case <-timeoutChan:
			return errors.New("timeout waiting for first event")
		case <-time.After(250 * time.Millisecond):
			// we continuously run a command to generate events
			if err := exec.Command("/usr/bin/true").Run(); err != nil {
				return err
			}
		}
	}
}

func waitRunningManager(t *testing.T) (*Manager, func()) {
	manager, cleanup := startManager(t)
	if err := checkManagerIsStarted(manager); err != nil {
		cleanup()
		t.Fatal(err)
	}
	return manager, cleanup
}

// run it with: go test -v -run TestNoVerifierFailures ./internal/bpf -count=1 -exec "sudo -E".
func TestNoVerifierFailures(t *testing.T) {
	enableLearning := true
	// Loading happens here so we can catch verifier errors without running the manager
	_, err := NewManager(newTestLogger(t), enableLearning, ebpf.LogLevelBranch)
	if err == nil {
		t.Log("BPF manager started successfully :)!!")
		return
	}
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		t.Log("Verifier errors detected:")
		for _, log := range verr.Log {
			t.Log(log)
		}
	}
	t.Log(err)
	t.FailNow()
}

func TestLearning(t *testing.T) {
	//////////////////////
	// Start BPF manager
	//////////////////////
	manager, cleanup := waitRunningManager(t)
	defer cleanup()

	//////////////////////
	// Setup the cgroup
	//////////////////////
	cgInfo, err := createTestCgroup()
	require.NoError(t, err, "Failed to create test cgroup")
	defer cgInfo.Close()

	require.NoError(t, runAndFindCommand(&runCommandArgs{
		manager:         manager,
		cgInfo:          &cgInfo,
		command:         "/usr/bin/true",
		channel:         learningChannel,
		shouldFindEvent: true,
	}))
}

func TestMonitorProtectMode(t *testing.T) {
	manager, cleanup := waitRunningManager(t)
	defer cleanup()

	//////////////////////
	// Setup the cgroup
	//////////////////////
	cgInfo, err := createTestCgroup()
	require.NoError(t, err, "Failed to create test cgroup")
	defer cgInfo.Close()

	//////////////////////
	// Populate the policy map
	//////////////////////
	mockPolicyID := uint64(42)

	// populate policy values
	// only `pol_str_maps_0` will be popoulated here, all the other maps won't be created.
	err = manager.GetPolicyValuesUpdateFunc()(mockPolicyID, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy values")

	// populate policy mode to monitor
	err = manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Monitor, UpdateMode)
	require.NoError(t, err, "Failed to set policy mode")

	// populate cgroup to track
	err = manager.GetCgroupPolicyUpdateFunc()(mockPolicyID, []uint64{cgInfo.id}, AddPolicyToCgroups)
	require.NoError(t, err, "Failed to add policy to cgroup")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	t.Log("Trying allowed binary in monitor mode")
	require.NoError(t, runAndFindCommand(&runCommandArgs{
		manager:         manager,
		cgInfo:          &cgInfo,
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}))

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in monitor mode")
	require.NoError(t, runAndFindCommand(&runCommandArgs{
		manager:         manager,
		cgInfo:          &cgInfo,
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
	require.NoError(t, runAndFindCommand(&runCommandArgs{
		manager:         manager,
		cgInfo:          &cgInfo,
		command:         tmpPath,
		channel:         monitoringChannel,
		shouldFindEvent: true,
	}))

	//////////////////////
	// Switch to enforcing mode
	//////////////////////
	t.Log("Switching to enforcing mode")
	err = manager.GetPolicyModeUpdateFunc()(mockPolicyID, policymode.Protect, UpdateMode)
	require.NoError(t, err, "Failed to set policy to protect")

	//////////////////////
	// Try a binary that is allowed
	//////////////////////
	// Should behave like the monitor mode
	t.Log("Trying allowed binary in enforcing mode")
	require.NoError(t, runAndFindCommand(&runCommandArgs{
		manager:         manager,
		cgInfo:          &cgInfo,
		command:         "/usr/bin/true",
		channel:         monitoringChannel,
		shouldFindEvent: false,
	}))

	//////////////////////
	// Try a binary that is not allowed
	//////////////////////
	t.Log("Trying not allowed binary in enforcing mode")
	require.NoError(t, runAndFindCommand(&runCommandArgs{
		manager:         manager,
		cgInfo:          &cgInfo,
		command:         "/usr/bin/who",
		channel:         monitoringChannel,
		shouldFindEvent: true,
		shouldEPERM:     true,
	}))

	//////////////////////
	// Try a binary that is not allowed and that is not in `pol_str_maps_0`
	//////////////////////
	t.Log("Trying binary with path len > 128 in enforcing mode")
	require.NoError(t, runAndFindCommand(&runCommandArgs{
		manager:         manager,
		cgInfo:          &cgInfo,
		command:         tmpPath,
		channel:         monitoringChannel,
		shouldEPERM:     true,
		shouldFindEvent: true,
	}))
}

func TestMultiplePolicies(t *testing.T) {
	manager, cleanup := waitRunningManager(t)
	defer cleanup()

	mockPolicyID1 := uint64(42)
	err := manager.GetPolicyValuesUpdateFunc()(mockPolicyID1, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 1 values")

	// We try to create 2 policies to check if `max_entries`
	// for string maps is really greater than 1.
	mockPolicyID2 := uint64(43)
	err = manager.GetPolicyValuesUpdateFunc()(mockPolicyID2, []string{"/usr/bin/who"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy 2 values")
}
