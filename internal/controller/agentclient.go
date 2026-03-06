package controller

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/internal/tlsutil"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const agentClientTimeout = 5 * time.Second

// agentClientFactory is responsible for creating agent clients.
type agentClientFactory struct {
	port        string
	mTLSEnabled bool
	tlsCertPath string
	tlsKeyPath  string
	caCertPath  string
}

func newAgentClientFactory(conf *AgentGRPCConfig) (*agentClientFactory, error) {
	if conf.Port == 0 {
		return nil, fmt.Errorf("invalid gRPC port: %d", conf.Port)
	}

	var tlsCertPath string
	var tlsKeyPath string
	var caCertPath string
	if conf.MTLSEnabled {
		if err := tlsutil.ValidateCertDir(conf.CertDirPath); err != nil {
			return nil, err
		}
		tlsCertPath = filepath.Join(conf.CertDirPath, tlsutil.CertFile)
		tlsKeyPath = filepath.Join(conf.CertDirPath, tlsutil.KeyFile)
		caCertPath = filepath.Join(conf.CertDirPath, tlsutil.CAFile)
	}
	return &agentClientFactory{
		port:        strconv.Itoa(conf.Port),
		tlsCertPath: tlsCertPath,
		tlsKeyPath:  tlsKeyPath,
		caCertPath:  caCertPath,
		mTLSEnabled: conf.MTLSEnabled,
	}, nil
}

func (f *agentClientFactory) getConnCredentials(podNamespacedName string) (credentials.TransportCredentials, error) {
	if !f.mTLSEnabled {
		return insecure.NewCredentials(), nil
	}

	// we get them at each new connection so that we manage certificate rotation.
	certPool, err := tlsutil.LoadCACertPool(f.caCertPath)
	if err != nil {
		return nil, err
	}

	clientCert, err := tlsutil.LoadKeyPair(f.tlsCertPath, f.tlsKeyPath)
	if err != nil {
		return nil, err
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

func (f *agentClientFactory) newClient(podIP, podName, podNamespace string) (*agentClient, error) {
	creds, err := f.getConnCredentials(fmt.Sprintf("%s.%s", podName, podNamespace))
	if err != nil {
		return nil, fmt.Errorf("failed to get connection credentials: %w", err)
	}

	host := net.JoinHostPort(podIP, f.port)
	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed host %s: %w", host, err)
	}

	return &agentClient{
		conn:   conn,
		client: pb.NewAgentObserverClient(conn),
	}, nil
}

// agentClientAPI this interface is used to mock the client in tests.
type agentClientAPI interface {
	listPoliciesStatus(ctx context.Context) (map[string]*pb.PolicyStatus, error)
	scrapeViolations(ctx context.Context) ([]*pb.ViolationRecord, error)
	close() error
}

// This is the implementation of agentClientAPI used in the production code.
type agentClient struct {
	conn   *grpc.ClientConn
	client pb.AgentObserverClient
}

func (c *agentClient) listPoliciesStatus(ctx context.Context) (map[string]*pb.PolicyStatus, error) {
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, agentClientTimeout)
	defer timeoutCancel()

	resp, err := c.client.ListPoliciesStatus(timeoutCtx, &pb.ListPoliciesStatusRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetPolicies(), nil
}

func (c *agentClient) scrapeViolations(ctx context.Context) ([]*pb.ViolationRecord, error) {
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, agentClientTimeout)
	defer timeoutCancel()

	resp, err := c.client.ScrapeViolations(timeoutCtx, &pb.ScrapeViolationsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetViolations(), nil
}

func (c *agentClient) close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
