package grpcexporter

import (
	"context"

	"log/slog"

	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
)

// agentObserver implements the AgentObserver gRPC server.
type agentObserver struct {
	pb.UnimplementedAgentObserverServer

	logger   *slog.Logger
	resolver *resolver.Resolver
}

func newAgentObserver(logger *slog.Logger, resolver *resolver.Resolver) *agentObserver {
	return &agentObserver{
		logger:   logger.With("component", "agent_observer"),
		resolver: resolver,
	}
}

// ListPoliciesStatus list policies inside the resolver and returns their status.
func (s *agentObserver) ListPoliciesStatus(
	ctx context.Context,
	_ *pb.ListPoliciesStatusRequest,
) (*pb.ListPoliciesStatusResponse, error) {
	out := &pb.ListPoliciesStatusResponse{
		Policies: make(map[string]*pb.PolicyStatus),
	}

	policies := s.resolver.ListPolicies()
	for _, policyName := range policies {
		out.Policies[policyName] = &pb.PolicyStatus{
			// todo!: we need to populate the real state here.
			State: pb.PolicyState_POLICY_STATE_READY,
			Mode:  pb.PolicyMode_POLICY_MODE_PROTECT,
		}
	}

	s.logger.DebugContext(ctx, "listed tracing policies", "count", len(out.GetPolicies()))
	return out, nil
}
