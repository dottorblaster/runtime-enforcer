package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type nodeInfo struct {
	issue    v1alpha1.NodeIssue
	policies map[string]*pb.PolicyStatus
}

// nodesInfoMap maps node names to their info.
// Structure: NodeName -> Info.
type nodesInfoMap map[string]nodeInfo

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies/status,verbs=get;update;patch

// WorkloadPolicyStatusSync reconciles a WorkloadPolicy status.
type WorkloadPolicyStatusSync struct {
	client.Client

	agentClientPool *grpcexporter.AgentClientPool
	updateInterval  time.Duration
	logger          logr.Logger
}

// WorkloadPolicyStatusSyncConfig holds the configuration for the WorkloadPolicyStatusSync.
type WorkloadPolicyStatusSyncConfig struct {
	AgentPoolConf  grpcexporter.AgentClientPoolConfig
	UpdateInterval time.Duration
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
		r.logger.V(1).Info("No WorkloadPolicies found, retrying later")
		return nil
	}

	clients, err := r.agentClientPool.UpdatePool(ctx, r.Client)
	if err != nil {
		return err
	}
	nodesInfo := make(nodesInfoMap, len(clients))

	for nodeName, client := range clients {
		if client == nil {
			r.logger.Info("cannot get a agent client for the node", "node", nodeName)
			nodesInfo[nodeName] = nodeInfo{
				policies: nil,
				issue: v1alpha1.NodeIssue{
					Code:    v1alpha1.NodeIssuePodNotReady,
					Message: "No agent client available",
				},
			}
			continue
		}

		// by default success state
		nodeIssue := v1alpha1.NodeIssue{
			Code:    v1alpha1.NodeIssueNone,
			Message: "",
		}
		var policies map[string]*pb.PolicyStatus
		policies, err = client.ListPoliciesStatus(ctx)
		if err != nil {
			// in case of error we close the connection and we will open a new one at the next sync
			r.agentClientPool.MarkStaleAgentClient(nodeName)
			r.logger.Error(err, "failed to get policies status", "node", nodeName)
			nodeIssue = v1alpha1.NodeIssue{
				Code:    v1alpha1.NodeIssueMissingPolicy,
				Message: fmt.Sprintf("cannot list node policies: %v", err),
			}
		} else if len(policies) == 0 {
			// if there are no policies for this pod we have an error because in previous steps
			// we checked that we have policies deployed in the cluster.
			r.logger.Error(errors.New("empty policy list"), "No policies found", "node", nodeName)
			nodeIssue = v1alpha1.NodeIssue{
				Code:    v1alpha1.NodeIssueMissingPolicy,
				Message: "empty policy list",
			}
		}
		nodesInfo[nodeName] = nodeInfo{
			policies: policies,
			issue:    nodeIssue,
		}
	}

	violationsByPolicy := r.getViolationsByPolicy(ctx, clients)

	// Now we iterate over all WSPs and update their status based on the collected policies status from the agents
	for _, wp := range wpList.Items {
		namespacedName := types.NamespacedName{Namespace: wp.Namespace, Name: wp.Name}
		if err = r.processWorkloadPolicy(ctx, &wp, nodesInfo, violationsByPolicy[namespacedName]); err != nil {
			r.logger.Error(
				err,
				"failed to process workload policy",
				"policy", wp.NamespacedName(),
			)
		}
	}

	return nil
}

// getViolationsByPolicy gets all the violations for a single policy.
func (r *WorkloadPolicyStatusSync) getViolationsByPolicy(
	ctx context.Context,
	clients map[string]grpcexporter.AgentClientAPI,
) map[types.NamespacedName][]v1alpha1.ViolationRecord {
	violationsByPolicy := make(map[types.NamespacedName][]v1alpha1.ViolationRecord)
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
			namespacedName, parseErr := parsePolicyNamespacedName(v.GetPolicyName())
			if parseErr != nil {
				r.logger.Error(parseErr, "skipping violation record", "node", nodeName)
				continue
			}
			rec := v1alpha1.ViolationRecord{
				Timestamp:      metav1.NewTime(v.GetTimestamp().AsTime()),
				PodName:        v.GetPodName(),
				ContainerName:  v.GetContainerName(),
				ExecutablePath: v.GetExecutablePath(),
				NodeName:       v.GetNodeName(),
				Action:         v.GetAction(),
			}
			violationsByPolicy[namespacedName] = append(violationsByPolicy[namespacedName], rec)
		}
	}

	return violationsByPolicy
}

// parsePolicyNamespacedName parses a "namespace/name" string into a NamespacedName.
// It returns an error if the string is not in the expected format, since all
// policies are namespaced resources.
func parsePolicyNamespacedName(s string) (types.NamespacedName, error) {
	parts := strings.SplitN(s, "/", 2) //nolint:mnd // namespace/name pair
	if len(parts) != 2 {               //nolint:mnd // namespace/name pair
		return types.NamespacedName{}, fmt.Errorf("invalid policy name %q: expected namespace/name format", s)
	}
	return types.NamespacedName{Namespace: parts[0], Name: parts[1]}, nil
}
