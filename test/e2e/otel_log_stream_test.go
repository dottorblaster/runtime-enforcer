package e2e_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	otlplogsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	logRecordChannelBufferSize = 100
	scannerBufferSize          = 1024 * 1024 // 1 MB
)

// OtelLogStream reads an io.ReadCloser (typically from the Kubernetes pod/logs
// API) and parses OTLP JSON log records emitted by the collector's file
// exporter. Parsed log records are sent to a buffered channel so that tests
// can consume them via WaitUntil.
type OtelLogStream struct {
	stream  io.ReadCloser
	records chan *otlplogsv1.LogRecord
	cancel  context.CancelFunc
}

func NewOtelLogStream(stream io.ReadCloser) *OtelLogStream {
	return &OtelLogStream{
		stream:  stream,
		records: make(chan *otlplogsv1.LogRecord, logRecordChannelBufferSize),
	}
}

func (s *OtelLogStream) Stop() {
	s.cancel()
	s.stream.Close()
}

// Start reads lines from the stream, unmarshals each as an OTLP LogsData JSON
// object (one per line, as written by the file exporter), and sends individual
// LogRecord values to the internal channel. It blocks until the context is
// cancelled.
func (s *OtelLogStream) Start(ctx context.Context, t *testing.T) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	scanner := bufio.NewScanner(s.stream)
	scanner.Buffer([]byte{}, scannerBufferSize)

	for {
		if !scanner.Scan() {
			// Stream closed or EOF – check context before retrying.
			select {
			case <-ctx.Done():
				return nil
			default:
				time.Sleep(time.Second)
				continue
			}
		}

		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var logsData otlplogsv1.LogsData
		if err := protojson.Unmarshal(line, &logsData); err != nil {
			// Not every line from the container is OTLP JSON (e.g. the
			// collector prints its own startup messages). Skip silently.
			t.Logf("OtelLogStream: skipping non-OTLP line: %v", err)
			continue
		}

		s.extractLogRecords(&logsData)
	}
}

func (s *OtelLogStream) extractLogRecords(data *otlplogsv1.LogsData) {
	for _, rl := range data.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				s.records <- lr
			}
		}
	}
}

// WaitUntil invokes cb for each log record received from the collector until
// cb returns true or the timeout expires.
func (s *OtelLogStream) WaitUntil(
	ctx context.Context,
	timeout time.Duration,
	cb func(record *otlplogsv1.LogRecord) bool,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return errors.New("timed out waiting for matching log record")
		case rec := <-s.records:
			if cb(rec) {
				return nil
			}
		}
	}
}

// LogRecordAttribute returns the string value of the attribute with the given
// key, or ("", false) if not found.
func LogRecordAttribute(rec *otlplogsv1.LogRecord, key string) (string, bool) {
	for _, attr := range rec.GetAttributes() {
		if attr.GetKey() == key {
			return attr.GetValue().GetStringValue(), true
		}
	}
	return "", false
}
