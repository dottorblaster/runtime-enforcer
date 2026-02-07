package events

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc/credentials"
)

// Init creates an OTEL log provider that exports violation events to the given
// gRPC endpoint over TLS. Unlike the trace pipeline (which reads from env vars),
// this uses an explicit endpoint to keep the violation event path separate from
// Security Hub traces. When caCertPath is non-empty, the connection verifies
// the collector's certificate against the provided CA; otherwise the system
// certificate pool is used.
func Init(ctx context.Context, endpoint, caCertPath string) (otellog.Logger, func(context.Context) error, error) {
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(endpoint),
	}

	if caCertPath != "" {
		caPem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read CA certificate %s: %w", caCertPath, err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPem) {
			return nil, nil, fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
		}
		tlsConfig := &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS13,
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}

	exporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	logger := provider.Logger("violation-reporter")
	return logger, provider.Shutdown, nil
}
