package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateCACertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLoadCACertPool(t *testing.T) {
	t.Run("valid PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ca.crt")
		if err := os.WriteFile(path, generateCACertPEM(t), 0o600); err != nil {
			t.Fatal(err)
		}

		pool, err := LoadCACertPool(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool == nil {
			t.Fatal("expected non-nil cert pool")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := LoadCACertPool(filepath.Join(t.TempDir(), "nonexistent.crt"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.crt")
		if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := LoadCACertPool(path)
		if err == nil {
			t.Fatal("expected error for invalid PEM")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.crt")
		if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := LoadCACertPool(path)
		if err == nil {
			t.Fatal("expected error for empty file")
		}
	})
}
