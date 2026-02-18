package nri

import (
	"context"
	"fmt"
	"log/slog"

	nrilog "github.com/containerd/nri/pkg/log"
)

// nriLogger adapts slog to the NRI log interface so stub messages are emitted as JSON.
type nriLogger struct {
	logger *slog.Logger
}

func newNRILogger(logger *slog.Logger) nrilog.Logger {
	return &nriLogger{logger: logger.With("component", "nri-stub")}
}

func (s *nriLogger) Debugf(ctx context.Context, format string, args ...interface{}) {
	s.logger.DebugContext(ctx, fmt.Sprintf(format, args...))
}

func (s *nriLogger) Infof(ctx context.Context, format string, args ...interface{}) {
	s.logger.InfoContext(ctx, fmt.Sprintf(format, args...))
}

func (s *nriLogger) Warnf(ctx context.Context, format string, args ...interface{}) {
	s.logger.WarnContext(ctx, fmt.Sprintf(format, args...))
}

func (s *nriLogger) Errorf(ctx context.Context, format string, args ...interface{}) {
	s.logger.ErrorContext(ctx, fmt.Sprintf(format, args...))
}
