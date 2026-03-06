package tlsutil

import (
	"crypto/x509"
	"fmt"
	"os"
)

// LoadCACertPool reads a PEM-encoded CA certificate from path and returns an
// x509.CertPool containing it. This is useful for setting up TLS connections
// that verify against a custom CA, and supports certificate rotation when
// called on each handshake.
func LoadCACertPool(path string) (*x509.CertPool, error) {
	caPem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPem) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", path)
	}
	return pool, nil
}
