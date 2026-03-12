package events

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/rancher-sandbox/runtime-enforcer/internal/tlsutil"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/grpc/credentials"
)

type protocol string

const (
	protocolGRPC         protocol = "grpc"
	protocolHTTPProtobuf protocol = "http/protobuf"
)

func stringToProtocol(s string) (protocol, error) {
	switch s {
	case "grpc":
		return protocolGRPC, nil
	case "http/protobuf":
		return protocolHTTPProtobuf, nil
	default:
		return "", fmt.Errorf("unsupported protocol: %s", s)
	}
}

func buildTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	// Validate that the CA certificate is readable at startup.
	if _, err := tlsutil.LoadCACertPool(caCertPath); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
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
	if clientCertPath != "" && clientKeyPath != "" {
		clientCert, err := tlsutil.LoadKeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	return cfg, nil
}

func createGRPCExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdklog.Exporter, error) {
	// if the user specified the correct path we shouldn't receive the http prefix here, but just to be sure.
	gRPCEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	insecure := caCertPath == ""
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(gRPCEndpoint),
	}
	if insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	} else {
		tlsConfig, err := buildTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}
	return otlploggrpc.New(ctx, opts...)
}

func createHTTPExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdklog.Exporter, error) {
	// first we check if we are in insecure mode
	insecure := strings.HasPrefix(endpoint, "http://")
	// Strip the scheme from the endpoint: WithEndpoint expects "host:port".
	httpEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(httpEndpoint),
	}

	if insecure {
		opts = append(opts, otlploghttp.WithInsecure())
	} else if caCertPath != "" {
		tlsConfig, err := buildTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsConfig))
	}
	return otlploghttp.New(ctx, opts...)
}

// Init creates an OTEL log provider that exports violation events to the given
// endpoint. The protocol can be either "grpc" or "http/protobuf".
// When caCertPath is non-empty, the connection verifies the collector's
// certificate against the provided CA; otherwise insecure mode is used.
// When clientCertPath and clientKeyPath are both non-empty, the client
// presents a TLS certificate for mTLS authentication.
func Init(
	ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath, protocol string,
) (otellog.Logger, func(context.Context) error, error) {
	var exporter sdklog.Exporter
	proto, err := stringToProtocol(protocol)
	if err != nil {
		return nil, nil, err
	}
	switch proto {
	case protocolGRPC:
		exporter, err = createGRPCExporter(ctx, endpoint, caCertPath, clientCertPath, clientKeyPath)
	case protocolHTTPProtobuf:
		exporter, err = createHTTPExporter(ctx, endpoint, caCertPath, clientCertPath, clientKeyPath)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	logger := provider.Logger("violation-reporter")
	return logger, provider.Shutdown, nil
}
