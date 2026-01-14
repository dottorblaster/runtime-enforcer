//nolint:testpackage // we are testing unexported functions
package bpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sync/errgroup"
)

//////////////////////
// Test Logger
//////////////////////

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

//////////////////////
// Channel helpers
//////////////////////

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

//////////////////////
// Cgroup runner
//////////////////////

type cgroupRunner struct {
	manager        *Manager
	managerCleanup func()
	cgInfo         cgroupInfo
}

func startManager(ctx context.Context, logger *slog.Logger) (*Manager, func(), error) {
	// We always enable learning in tests for now so that we can wait for the first event to come
	// and understand that BPF programs are loaded and running
	enableLearning := true
	manager, err := NewManager(logger, enableLearning, ebpf.LogLevelBranch)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create BPF manager: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return manager.Start(ctx)
	})

	return manager, func() {
		cancel()
		g.Wait()
	}, nil
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

func waitRunningManager(t *testing.T) (*Manager, func(), error) {
	manager, cleanup, err := startManager(t.Context(), newTestLogger(t))
	if err != nil {
		return nil, nil, err
	}

	if err = checkManagerIsStarted(manager); err != nil {
		cleanup()
		return nil, nil, err
	}
	return manager, cleanup, nil
}

type runCommandArgs struct {
	command         string
	channel         ChannelType
	shouldEPERM     bool
	shouldFindEvent bool
}

func (r *cgroupRunner) runAndFindCommand(args *runCommandArgs) error {
	err := r.cgInfo.RunInCgroup(args.command, []string{})
	if args.shouldEPERM {
		if err == nil || !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("expected EPERM error, got: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to run %s in cgroup: %w", args.command, err)
	}

	// Get the event
	err = r.manager.findEventInChannel(args.channel, r.cgInfo.id, args.command)
	if args.shouldFindEvent {
		if err != nil {
			return fmt.Errorf(
				"failed to find (command: %s, cgroup: %d) in channel %s: %w",
				args.command,
				r.cgInfo.id,
				args.channel,
				err,
			)
		}
	} else if err == nil {
		return fmt.Errorf("Did not expect to find (command: %s, cgroup: %d)", args.command, r.cgInfo.id)
	}
	return nil
}

func (r *cgroupRunner) close() {
	r.cgInfo.Close()
	r.managerCleanup()
}

func newCgroupRunner(t *testing.T) (*cgroupRunner, error) {
	// Start the manager and wait for it to be ready
	manager, cleanup, err := startManager(t.Context(), newTestLogger(t))
	if err != nil {
		return nil, err
	}

	if err = checkManagerIsStarted(manager); err != nil {
		cleanup()
		return nil, err
	}

	// Create the cgroup where we will run our commands
	cgInfo, err := createTestCgroup()
	if err != nil {
		cleanup()
		return nil, err
	}

	return &cgroupRunner{
		manager:        manager,
		managerCleanup: cleanup,
		cgInfo:         cgInfo,
	}, nil
}
