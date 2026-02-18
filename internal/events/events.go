package events

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// Init creates an OTEL log provider that exports violation events to the given
// gRPC endpoint over TLS. Unlike the trace pipeline (which reads from env vars),
// this uses an explicit endpoint to keep the violation event path separate from
// Security Hub traces.
func Init(ctx context.Context, endpoint string) (otellog.Logger, func(context.Context) error, error) {
	exporter, err := otlploggrpc.New(ctx,
		otlploggrpc.WithEndpoint(endpoint),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	logger := provider.Logger("violation-reporter")
	return logger, provider.Shutdown, nil
}
