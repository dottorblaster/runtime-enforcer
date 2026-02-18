package grpcexporter

import (
	"context"

	"log/slog"

	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"github.com/rancher-sandbox/runtime-enforcer/internal/violationbuf"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// agentObserver implements the AgentObserver gRPC server.
type agentObserver struct {
	pb.UnimplementedAgentObserverServer

	logger          *slog.Logger
	resolver        *resolver.Resolver
	violationBuffer *violationbuf.Buffer
}

func newAgentObserver(logger *slog.Logger, resolver *resolver.Resolver, violationBuffer *violationbuf.Buffer) *agentObserver {
	return &agentObserver{
		logger:          logger.With("component", "agent_observer"),
		resolver:        resolver,
		violationBuffer: violationBuffer,
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

// ScrapeViolations drains the agent's in-memory violation buffer and returns
// all accumulated records since the last scrape.
func (s *agentObserver) ScrapeViolations(
	ctx context.Context,
	_ *pb.ScrapeViolationsRequest,
) (*pb.ScrapeViolationsResponse, error) {
	records := s.violationBuffer.Drain()

	out := &pb.ScrapeViolationsResponse{
		Violations: make([]*pb.ViolationRecord, 0, len(records)),
	}

	for _, rec := range records {
		out.Violations = append(out.Violations, &pb.ViolationRecord{
			Timestamp:      timestamppb.New(rec.Timestamp),
			PodName:        rec.PodName,
			ContainerName:  rec.ContainerName,
			ExecutablePath: rec.ExePath,
			NodeName:       rec.NodeName,
			Action:         rec.Action,
			PolicyName:     rec.Namespace + "/" + rec.PolicyName,
			Count:          rec.Count,
		})
	}

	s.logger.DebugContext(ctx, "scraped violations", "count", len(out.GetViolations()))
	return out, nil
}
