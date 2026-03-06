package grpcexporter

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// AgentClientFactory is responsible for creating agent clients.
type AgentClientFactory struct {
	port        string
	mTLSEnabled bool
	tlsCertPath string
	tlsKeyPath  string
	caCertPath  string
}

type AgentFactoryConfig struct {
	MTLSEnabled bool
	CertDirPath string
	Port        int
}

func NewAgentClientFactory(conf *AgentFactoryConfig) (*AgentClientFactory, error) {
	if conf.Port == 0 {
		return nil, fmt.Errorf("invalid gRPC port: %d", conf.Port)
	}

	var tlsCertPath string
	var tlsKeyPath string
	var caCertPath string
	if conf.MTLSEnabled {
		// if mTLS is enabled, we need to validate the cert path
		if conf.CertDirPath == "" {
			return nil, errors.New("certificate directory path is empty")
		}
		if _, err := os.Stat(conf.CertDirPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("certificate directory does not exist: %w", err)
		}
		tlsCertPath = filepath.Join(conf.CertDirPath, tlsCertFile)
		tlsKeyPath = filepath.Join(conf.CertDirPath, tlsKeyFile)
		caCertPath = filepath.Join(conf.CertDirPath, caCertFile)
		_, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load key pair: %w", err)
		}
	}
	return &AgentClientFactory{
		port:        strconv.Itoa(conf.Port),
		tlsCertPath: tlsCertPath,
		tlsKeyPath:  tlsKeyPath,
		caCertPath:  caCertPath,
		mTLSEnabled: conf.MTLSEnabled,
	}, nil
}

func (f *AgentClientFactory) getConnCredentials(podNamespacedName string) (credentials.TransportCredentials, error) {
	if !f.mTLSEnabled {
		return insecure.NewCredentials(), nil
	}

	// we get them at each new connection so that we manage certificate rotation.
	caPem, err := os.ReadFile(f.caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPem) {
		return nil, errors.New("failed to parse CA")
	}

	clientCert, err := tls.LoadX509KeyPair(f.tlsCertPath, f.tlsKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
		// the service name in the server certificate will be in this form
		ServerName: podNamespacedName,
	}
	return credentials.NewTLS(tlsConfig), nil
}

func (f *AgentClientFactory) NewClient(podIP, podName, podNamespace string) (*AgentClient, error) {
	creds, err := f.getConnCredentials(fmt.Sprintf("%s.%s", podName, podNamespace))
	if err != nil {
		return nil, fmt.Errorf("failed to get connection credentials: %w", err)
	}

	host := net.JoinHostPort(podIP, f.port)
	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed host %s: %w", host, err)
	}

	return &AgentClient{
		conn:   conn,
		client: pb.NewAgentObserverClient(conn),
	}, nil
}
