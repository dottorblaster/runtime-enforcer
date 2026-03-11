package e2e_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

const (
	logRecordChannelBufferSize = 100
	scannerBufferSize          = 1024 * 1024 // 1 MB
)

// otlpKeyValue mirrors the OTLP JSON attribute representation.
type otlpKeyValue struct {
	Key   string `json:"key"`
	Value struct {
		StringValue string `json:"stringValue"`
	} `json:"value"`
}

// otlpLogRecord mirrors the OTLP JSON LogRecord representation.
type otlpLogRecord struct {
	SeverityText string         `json:"severityText"`
	EventName    string         `json:"eventName"`
	Body         json.RawMessage `json:"body"`
	Attributes   []otlpKeyValue `json:"attributes"`
}

// otlpScopeLogs groups log records under an instrumentation scope.
type otlpScopeLogs struct {
	LogRecords []otlpLogRecord `json:"logRecords"`
}

// otlpResourceLogs is a single resource entry containing scope logs.
type otlpResourceLogs struct {
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

// otlpLogsData mirrors the OTLP JSON file exporter output for logs.
// The file exporter may write either {"resourceLogs":[...]} (wrapped)
// or {"resource":...,"scopeLogs":[...]} (unwrapped, one entry per line).
type otlpLogsData struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

// OtelLogStream reads an io.ReadCloser (typically from the Kubernetes pod/logs
// API) and parses OTLP JSON log records emitted by the collector's file
// exporter. Parsed log records are sent to a buffered channel so that tests
// can consume them via WaitUntil.
type OtelLogStream struct {
	stream  io.ReadCloser
	records chan *otlpLogRecord
	cancel  context.CancelFunc
}

func NewOtelLogStream(stream io.ReadCloser) *OtelLogStream {
	return &OtelLogStream{
		stream:  stream,
		records: make(chan *otlpLogRecord, logRecordChannelBufferSize),
	}
}

func (s *OtelLogStream) Stop() {
	s.cancel()
	s.stream.Close()
}

// Start reads lines from the stream, unmarshals each as an OTLP JSON object
// (one per line, as written by the file exporter), and sends individual log
// records to the internal channel. It blocks until the context is cancelled.
func (s *OtelLogStream) Start(ctx context.Context, t *testing.T) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	scanner := bufio.NewScanner(s.stream)
	scanner.Buffer([]byte{}, scannerBufferSize)

	for {
		if !scanner.Scan() {
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
		if len(line) == 0 || line[0] != '{' {
			continue
		}

		records := s.parseLogRecords(line)
		for i := range records {
			s.records <- &records[i]
		}
	}
}

// parseLogRecords tries to extract log records from a JSON line. It handles
// both the wrapped format ({"resourceLogs":[...]}) and the unwrapped format
// where a single resource entry is written per line ({"resource":...,"scopeLogs":[...]}).
func (s *OtelLogStream) parseLogRecords(line []byte) []otlpLogRecord {
	// Try the wrapped format first: {"resourceLogs":[...]}
	var data otlpLogsData
	if err := json.Unmarshal(line, &data); err == nil {
		var records []otlpLogRecord
		for _, rl := range data.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				records = append(records, sl.LogRecords...)
			}
		}
		if len(records) > 0 {
			return records
		}
	}

	// Fall back to the unwrapped format: {"resource":...,"scopeLogs":[...]}
	var single otlpResourceLogs
	if err := json.Unmarshal(line, &single); err == nil {
		var records []otlpLogRecord
		for _, sl := range single.ScopeLogs {
			records = append(records, sl.LogRecords...)
		}
		return records
	}

	return nil
}

// WaitUntil invokes cb for each log record received from the collector until
// cb returns true or the timeout expires.
func (s *OtelLogStream) WaitUntil(
	ctx context.Context,
	timeout time.Duration,
	cb func(record *otlpLogRecord) bool,
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
func LogRecordAttribute(rec *otlpLogRecord, key string) (string, bool) {
	for _, attr := range rec.Attributes {
		if attr.Key == key {
			return attr.Value.StringValue, true
		}
	}
	return "", false
}
