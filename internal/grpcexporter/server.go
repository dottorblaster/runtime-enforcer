package grpcexporter

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
)

type Server struct {
	port     int
	logger   *slog.Logger
	resolver *resolver.Resolver
}

func New(logger *slog.Logger, port int, resolver *resolver.Resolver) *Server {
	return &Server{
		logger:   logger.With("component", "grpc_exporter"),
		port:     port,
		resolver: resolver,
	}
}

func (s *Server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	addr := fmt.Sprintf(":%d", s.port)
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterAgentObserverServer(grpcServer, newAgentObserver(s.logger, s.resolver))
	s.logger.InfoContext(ctx, "Starting gRPC exporter", "addr", addr)
	return grpcServer.Serve(listener)
}
