package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/time/rate"
)

const (
	// used in unit tests.
	suppressionMsg           = "logs suppressed by rate limiting"
	policyModeMissingMessage = "policy mode missing"

	// Log keys.
	msgLogKey             = "msg"
	cpuLogKey             = "cpu"
	tidLogKey             = "tid"
	pidLogKey             = "pid"
	cgroupTrackerIDLogKey = "cgroup_tracker_id"
	commLogKey            = "comm"
	policyIDLogKey        = "policy_id"
	modeLogKey            = "mode"
	suppressedCountLogKey = "count"
	suppressedLogTypeKey  = "log_type"
)

type logRateLimiter struct {
	limiter    *rate.Limiter
	suppressed int64
}

var (
	//nolint:gochecknoglobals // Rate limiter for exec events 1 token per second, burst of 1
	dropExecLimiter = &logRateLimiter{
		limiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
	}
	//nolint:gochecknoglobals // Rate limiter for exec events 1 token per second, burst of 1
	dropViolationLimiter = &logRateLimiter{
		limiter: rate.NewLimiter(rate.Every(1*time.Second), 1),
	}
)

func (l *logRateLimiter) logEvent(ctx context.Context,
	logger *slog.Logger,
	evt *bpfLogEvt,
	msg string,
	level slog.Level,
	additionalArgs ...any) {
	if !l.limiter.Allow() {
		l.suppressed++
		return
	}

	if l.suppressed > 0 {
		logger.Log(ctx, level, suppressionMsg,
			suppressedCountLogKey, l.suppressed,
			suppressedLogTypeKey, msg,
		)
		l.suppressed = 0
	}
	logEvent(ctx, logger, evt, msg, level, additionalArgs...)
}

func getComm(evt *bpfLogEvt) string {
	// Reinterpret the []int8 (C char array) as []byte without copying,
	// then trim at the first NUL byte.
	commBytes := unsafe.Slice((*byte)(unsafe.Pointer(&evt.Comm[0])), len(evt.Comm))
	n := bytes.IndexByte(commBytes, 0)
	if n == -1 {
		// if there is no null terminator we return the full string
		n = len(commBytes)
	}
	return string(commBytes[:n])
}

func logEvent(
	ctx context.Context,
	logger *slog.Logger,
	evt *bpfLogEvt,
	msg string,
	level slog.Level,
	additionalArgs ...any,
) {
	attrs := []any{
		tidLogKey, evt.Pid,
		pidLogKey, evt.Tgid,
		commLogKey, getComm(evt),
		cgroupTrackerIDLogKey, evt.CgTrackerId,
	}
	attrs = append(attrs, additionalArgs...)
	logger.Log(ctx, level, msg, attrs...)
}

func logEventMsg(ctx context.Context, logger *slog.Logger, evt *bpfLogEvt) {
	switch evt.Code {
	case bpfLogEventCodeLOG_FAIL_TO_LOOKUP_EVT_MAP:
		// arg1 is CPU
		logEvent(ctx, logger, evt, "failed to lookup process event in per-cpu map", slog.LevelError,
			cpuLogKey, evt.Arg1)
	case bpfLogEventCodeLOG_MISSING_FILE_STRUCT:
		logEvent(ctx, logger, evt, "executable with missing file struct", slog.LevelError)
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_PATH:
		logEvent(ctx, logger, evt, "failed to resolve path", slog.LevelWarn)
	case bpfLogEventCodeLOG_EMPTY_PATH:
		logEvent(ctx, logger, evt, "empty path detected", slog.LevelWarn)
	case bpfLogEventCodeLOG_FAIL_TO_COPY_EXEC_PATH:
		logEvent(ctx, logger, evt, "failed to copy exec path", slog.LevelError)
	case bpfLogEventCodeLOG_DROP_EXEC_EVENT:
		dropExecLimiter.logEvent(ctx, logger, evt, "dropped exec event", slog.LevelWarn)
	case bpfLogEventCodeLOG_PATH_LEN_TOO_LONG:
		logEvent(ctx, logger, evt, "path length too long", slog.LevelWarn)
	case bpfLogEventCodeLOG_POLICY_MODE_MISSING:
		// arg1 is the policy ID
		logEvent(ctx, logger, evt, "policy mode missing", slog.LevelWarn,
			policyIDLogKey, evt.Arg1)
	case bpfLogEventCodeLOG_DROP_VIOLATION:
		// arg1 is the policy ID
		// arg2 is the mode
		dropViolationLimiter.logEvent(ctx, logger, evt, "dropped violation event", slog.LevelWarn,
			policyIDLogKey, evt.Arg1,
			modeLogKey, evt.Arg2)
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_CGROUP_ID:
		logEvent(ctx, logger, evt, "failed to resolve cgroup id", slog.LevelWarn)
	case bpfLogEventCodeLOG_FAIL_TO_RESOLVE_PARENT_CGROUP_ID:
		logEvent(ctx, logger, evt, "failed to resolve parent cgroup id", slog.LevelWarn)
	default:
		logger.ErrorContext(ctx, "unknown log event type", "type", evt.Code)
	}
}

func (m *Manager) loggerStart(ctx context.Context) error {
	buf := m.objs.RingbufLogs
	rd, err := ringbuf.NewReader(buf)
	if err != nil {
		return fmt.Errorf("opening %s ringbuf reader: %w", buf.String(), err)
	}

	go func() {
		<-ctx.Done()
		if err = rd.Close(); err != nil {
			m.logger.ErrorContext(ctx, "closing ringbuf reader", "error", err)
		}
	}()

	var record ringbuf.Record
	for {
		record, err = rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				m.logger.InfoContext(ctx, "ringbuf reader closed")
				return nil
			}
			return fmt.Errorf("reading from reader: %w", err)
		}

		buf := bytes.NewBuffer(record.RawSample)
		var evt bpfLogEvt
		if err = binary.Read(buf, binary.LittleEndian, &evt); err != nil {
			m.logger.ErrorContext(ctx, "parsing ringbuf event", "error", err)
			continue
		}
		logEventMsg(ctx, m.logger, &evt)
	}
}
