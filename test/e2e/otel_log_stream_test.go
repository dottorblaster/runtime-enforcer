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

// otlpLogsData mirrors the OTLP JSON file exporter output for logs.
type otlpLogsData struct {
	ResourceLogs []struct {
		ScopeLogs []struct {
			LogRecords []otlpLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
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

		var data otlpLogsData
		if err := json.Unmarshal(line, &data); err != nil {
			continue
		}

		for i := range data.ResourceLogs {
			for j := range data.ResourceLogs[i].ScopeLogs {
				for k := range data.ResourceLogs[i].ScopeLogs[j].LogRecords {
					s.records <- &data.ResourceLogs[i].ScopeLogs[j].LogRecords[k]
				}
			}
		}
	}
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
