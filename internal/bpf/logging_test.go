package bpf

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

type memoryWriter struct {
	mu       sync.Mutex
	jsonLogs []map[string]any
}

func (w *memoryWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var data map[string]any
	if err := json.Unmarshal(p, &data); err != nil {
		return 0, err
	}
	w.jsonLogs = append(w.jsonLogs, data)
	return len(p), nil
}

// hasLogWithFields returns true if at least one of the log lines contains all the provided key-value pairs (fields is not empty).
func (w *memoryWriter) hasLogWithFields(fields map[string]string) bool {
	for _, logLine := range w.jsonLogs {
		foundAll := true
		for k, v := range fields {
			val, ok := logLine[k]
			if !ok || fmt.Sprintf("%v", val) != v {
				foundAll = false
				break
			}
		}
		if foundAll {
			return true
		}
	}
	return false
}

// assertHasLogWithFields fails the test if no log line contains all the provided key-value pairs.
func (w *memoryWriter) assertHasLogWithFields(t *testing.T, fields map[string]string) {
	t.Helper()
	require.Eventually(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		if !w.hasLogWithFields(fields) {
			t.Logf("No log found with the required fields: %v\nAll logs:\n", fields)
			for i, logLine := range w.jsonLogs {
				t.Logf("Log #%d: %v", i, logLine)
			}
			return false
		}
		return true
	}, 2*time.Second, 500*time.Millisecond, "wait for log with fields to appear")
}

func TestLogRateLimiter(t *testing.T) {
	// 1 token per second, burst of 1
	rateLimiter := &logRateLimiter{limiter: rate.NewLimiter(rate.Every(1*time.Second), 1)}
	exampleMsg := "example_msg"

	memoryWriter := &memoryWriter{}
	logger := slog.New(slog.NewJSONHandler(memoryWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "logging_test")

	// Create a burst of data
	for range 100 {
		rateLimiter.logEvent(t.Context(), logger, &bpfLogEvt{}, exampleMsg, slog.LevelInfo)
	}

	// We wait until there is a new token available
	require.Eventually(t, func() bool {
		return rateLimiter.limiter.Tokens() == 1
	}, 4*time.Second, 1*time.Second, "wait for a new token to be available")

	// When we are sure we have a new token, we log another event and we check for the suppression log
	rateLimiter.logEvent(t.Context(), logger, &bpfLogEvt{}, exampleMsg, slog.LevelInfo)

	// we expect to see both the original and suppression messages
	memoryWriter.assertHasLogWithFields(t, map[string]string{
		msgLogKey: exampleMsg,
	})
	memoryWriter.assertHasLogWithFields(t, map[string]string{
		msgLogKey:            suppressionMsg,
		suppressedLogTypeKey: exampleMsg,
	})
}

func TestLogMissingPolicyMode(t *testing.T) {
	memoryWriter := &memoryWriter{}
	logger := slog.New(slog.NewJSONHandler(memoryWriter, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})).With("component", "logging_test")

	runner, err := newCgroupRunnerWithLogger(t, logger)
	require.NoError(t, err, "Failed to create cgroup runner")
	defer runner.close()

	mockPolicyID := uint64(42)

	// populate policy values
	err = runner.manager.GetPolicyUpdateBinariesFunc()(mockPolicyID, []string{"/usr/bin/true"}, AddValuesToPolicy)
	require.NoError(t, err, "Failed to add policy values")

	// we don't populate the policy -> mode association on purpose so that we will trigger a log ebpf side.

	// populate cgroup to track
	err = runner.manager.GetCgroupPolicyUpdateFunc()(mockPolicyID, []uint64{runner.cgInfo.id}, AddPolicyToCgroups)
	require.NoError(t, err, "Failed to add policy to cgroup")

	// We throw a binary that is not allowed
	require.NoError(t, runner.runAndFindCommand(&runCommandArgs{
		command: "/usr/bin/who",
		channel: monitoringChannel,
		// we shouldn't find the event because we don't send it to userspace if we don't find the mode.
		shouldFindEvent: false,
	}))

	// we expect our policy missing log
	memoryWriter.assertHasLogWithFields(t, map[string]string{
		msgLogKey:             policyModeMissingMessage,
		policyIDLogKey:        strconv.FormatUint(mockPolicyID, 10),
		cgroupTrackerIDLogKey: strconv.FormatUint(runner.cgInfo.id, 10),
	})
}
