package events

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/rancher-sandbox/runtime-enforcer/internal/tlsutil"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc/credentials"
)

// Init creates an OTEL log provider that exports violation events to the given
// gRPC endpoint over TLS. This uses an explicit endpoint to keep the violation
// event path orthogonal. When caCertPath is non-empty, the connection verifies
// the collector's certificate against the provided CA; otherwise the system
// certificate pool is used.
func Init(ctx context.Context, endpoint, caCertPath string) (otellog.Logger, func(context.Context) error, error) {
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(endpoint),
	}

	if caCertPath != "" {
		// Validate that the CA certificate is readable at startup.
		if _, err := tlsutil.LoadCACertPool(caCertPath); err != nil {
			return nil, nil, err
		}
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS13,
			// Skip the default verification (static RootCAs) so we can
			// re-read the CA file on every handshake to handle rotation.
			InsecureSkipVerify: true, //nolint:gosec // verification is done in VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error {
				certPool, err := tlsutil.LoadCACertPool(caCertPath)
				if err != nil {
					return err
				}
				opts := x509.VerifyOptions{
					Roots:         certPool,
					DNSName:       cs.ServerName,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err = cs.PeerCertificates[0].Verify(opts)
				return err
			},
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
