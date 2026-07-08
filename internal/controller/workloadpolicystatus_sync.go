package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/loglevel"

	otellog "go.opentelemetry.io/otel/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies/status,verbs=get;update;patch

// WorkloadPolicyStatusSync reconciles a WorkloadPolicy status.
type WorkloadPolicyStatusSync struct {
	client.Client

	agentClientPool *grpcexporter.AgentClientPool
	updateInterval  time.Duration
	logger          logr.Logger
	eventLogger     otellog.Logger
}

// WorkloadPolicyStatusSyncConfig holds the configuration for the WorkloadPolicyStatusSync.
type WorkloadPolicyStatusSyncConfig struct {
	AgentPoolConf  grpcexporter.AgentClientPoolConfig
	UpdateInterval time.Duration
	EventLogger    otellog.Logger
}

func NewWorkloadPolicyStatusSync(
	c client.Client,
	config *WorkloadPolicyStatusSyncConfig,
) (*WorkloadPolicyStatusSync, error) {
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("invalid update interval: %v", config.UpdateInterval)
	}

	agentClientPool, err := grpcexporter.NewAgentClientPool(config.AgentPoolConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent client pool: %w", err)
	}

	return &WorkloadPolicyStatusSync{
		Client:          c,
		agentClientPool: agentClientPool,
		updateInterval:  config.UpdateInterval,
		eventLogger:     config.EventLogger,
	}, nil
}

func (r *WorkloadPolicyStatusSync) Start(ctx context.Context) error {
	r.logger = log.FromContext(ctx).WithName("WorkloadPolicyStatusSync")
	r.logger.Info("Starting with", "interval", r.updateInterval)
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Closing")
			return nil
		// today we keep this runnable single-threaded so after each sync we wait again `updateInterval`.
		case <-time.After(r.updateInterval):
			if err := r.sync(ctx); err != nil {
				r.logger.Error(err, "Failed to sync")
			}
		}
	}
}

func (r *WorkloadPolicyStatusSync) sync(
	ctx context.Context,
) error {
	// As first step, we list all WorkloadPolicies, if there are none, we can reschedule and exit early
	var wpList v1alpha1.WorkloadPolicyList
	if err := r.List(ctx, &wpList); err != nil {
		return err
	}

	if len(wpList.Items) == 0 {
		r.logger.V(loglevel.VerbosityDebug).Info("No WorkloadPolicies found, retrying later")
		return nil
	}

	clients, err := r.agentClientPool.UpdatePool(ctx, r.Client)
	if err != nil {
		return err
	}

	violationsByPolicy := r.getViolationsByPolicy(ctx, clients)
	nodeStatusByPolicy := r.getNodeStatusByPolicy(ctx, clients, wpList.Items)

	// Now we iterate over all WSPs and update their status based on the collected policies status from the agents
	for _, wp := range wpList.Items {
		policyName := wp.NamespacedName()
		if err = r.processWorkloadPolicy(
			ctx,
			&wp,
			nodeStatusByPolicy[policyName],
			violationsByPolicy[policyName],
		); err != nil {
			r.logger.Error(
				err,
				"failed to process workload policy",
				"policy", policyName,
			)
		}
	}

	return nil
}

// getViolationsByPolicy gets all the violations for a single policy.
func (r *WorkloadPolicyStatusSync) getViolationsByPolicy(
	ctx context.Context,
	clients map[string]grpcexporter.AgentClientAPI,
) map[string][]v1alpha1.ViolationRecord {
	violationsByPolicy := make(map[string][]v1alpha1.ViolationRecord)
	for nodeName, client := range clients {
		if client == nil {
			r.logger.Info("cannot get a agent client for the node", "node", nodeName)
			continue
		}
		pbViolations, err := client.ScrapeViolations(ctx)
		if err != nil {
			r.agentClientPool.MarkStaleAgentClient(nodeName)
			r.logger.Error(err, "failed to scrape violations", "node", nodeName)
			continue
		}
		for _, v := range pbViolations {
			namespacedName := v.GetPolicyName()
			rec := v1alpha1.ViolationRecord{
				Timestamp:      metav1.NewTime(v.GetTimestamp().AsTime()),
				PodName:        v.GetPodName(),
				ContainerName:  v.GetContainerName(),
				ExecutablePath: v.GetExecutablePath(),
				NodeName:       v.GetNodeName(),
				Action:         v.GetAction(),
				WorkloadName:   v.GetWorkloadName(),
				WorkloadKind:   v.GetWorkloadKind(),
			}
			violationsByPolicy[namespacedName] = append(violationsByPolicy[namespacedName], rec)
		}
	}

	return violationsByPolicy
}

func (r *WorkloadPolicyStatusSync) emitAcknowledgedViolationOtelLog(
	ctx context.Context,
	violation v1alpha1.ViolationRecord,
	reason string,
) {
	if r.eventLogger == nil {
		return
	}

	var rec otellog.Record
	rec.SetEventName("policy_violation_acknowledged")
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetBody(otellog.StringValue("policy_violation_acknowledged"))
	rec.SetTimestamp(time.Now())
	rec.AddAttributes(
		otellog.Int64("id", violation.ID),
		otellog.String("timestamp", violation.Timestamp.UTC().Format(time.RFC3339)),
		otellog.String("reason", reason),
		otellog.String("k8s.pod.name", violation.PodName),
		otellog.String("container.name", violation.ContainerName),
		otellog.String("proc.exepath", violation.ExecutablePath),
		otellog.String("node.name", violation.NodeName),
		otellog.String("action", violation.Action),
		otellog.String("workload.name", violation.WorkloadName),
		otellog.String("workload.kind", violation.WorkloadKind),
	)

	r.eventLogger.Emit(ctx, rec)
}
