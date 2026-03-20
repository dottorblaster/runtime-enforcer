// Package httpserverlogger implements a custom [slog.Handler] to filter out specific log
// messages from golang HTTP server
package httpserverlogger

import (
	"context"
	"log/slog"
	"strings"
)

type ServerErrorLogHandler struct {
	h slog.Handler
}

var _ slog.Handler = (*ServerErrorLogHandler)(nil)

func NewServerErrorLogHandler(h slog.Handler) *ServerErrorLogHandler {
	return &ServerErrorLogHandler{
		h: h,
	}
}

func (s *ServerErrorLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return s.h.Enabled(ctx, level)
}

func (s *ServerErrorLogHandler) Handle(ctx context.Context, r slog.Record) error {
	// It happens when we probe webhook from agent.
	// When we do this, because no valid TLS handshake is done,
	// the error message will be printed in operator from the underlying http server.
	// More information and the workaround can be found here: https://github.com/golang/go/issues/26918#top
	if strings.HasPrefix(r.Message, "http: TLS handshake error from") &&
		strings.HasSuffix(r.Message, ": EOF") {
		return nil
	}
	return s.h.Handle(ctx, r)
}

func (s *ServerErrorLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ServerErrorLogHandler{h: s.h.WithAttrs(attrs)}
}

func (s *ServerErrorLogHandler) WithGroup(name string) slog.Handler {
	return &ServerErrorLogHandler{h: s.h.WithGroup(name)}
}
