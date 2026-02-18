package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"

	corev1 "k8s.io/api/core/v1"
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

	conns              map[string]agentClientAPI
	agentClientFactory *agentClientFactory
	updateInterval     time.Duration
	agentNamespace     string
	agentLabelSelector map[string]string
	logger             logr.Logger
}

type AgentGRPCConfig struct {
	MTLSEnabled bool
	CertDirPath string
	Port        int
}

// WorkloadPolicyStatusSyncConfig holds the configuration for the WorkloadPolicyStatusSync.
type WorkloadPolicyStatusSyncConfig struct {
	AgentGRPCConf      AgentGRPCConfig
	UpdateInterval     time.Duration
	AgentNamespace     string
	AgentLabelSelector string
}

func NewWorkloadPolicyStatusSync(
	c client.Client,
	config *WorkloadPolicyStatusSyncConfig,
) (*WorkloadPolicyStatusSync, error) {
	if config.UpdateInterval <= 0 {
		return nil, fmt.Errorf("invalid update interval: %v", config.UpdateInterval)
	}

	agentLabelSelector := make(map[string]string)
	labels := strings.Split(config.AgentLabelSelector, ",")
	for _, label := range labels {
		parts := strings.Split(label, "=")
		if len(parts) != 2 { //nolint:mnd // label is composed of 2 parts
			return nil, fmt.Errorf("label should be in the format 'key=value': %s. Invalid selector %s",
				label,
				config.AgentLabelSelector)
		}
		agentLabelSelector[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	factory, err := newAgentClientFactory(&config.AgentGRPCConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent client factory: %w", err)
	}

	return &WorkloadPolicyStatusSync{
		Client:             c,
		conns:              make(map[string]agentClientAPI),
		agentClientFactory: factory,
		updateInterval:     config.UpdateInterval,
		agentNamespace:     config.AgentNamespace,
		agentLabelSelector: agentLabelSelector,
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
		r.logger.Info("No WorkloadPolicies found, retrying later")
		return nil
	}

	// Get all pods with the agent label in the agent namespace
	var podList corev1.PodList
	if err := r.List(ctx, &podList,
		client.InNamespace(r.agentNamespace),
		client.MatchingLabels(r.agentLabelSelector),
	); err != nil {
		return err
	}

	r.logger.V(1).Info("List agent pods", "numPods", len(podList.Items))
	if len(podList.Items) == 0 {
		// we should have pods running the agent, so if we don't find any, we return an error
		return errors.New("no agent pods found")
	}

	// remove stale connections.
	r.gcStaleConnections(&podList)

	nodesInfo := make(nodesInfoMap, len(podList.Items))

	for _, pod := range podList.Items {
		if !isPodReady(&pod) {
			r.logger.Info("Pod not ready, retrying later", "pod", pod.Name)
			// In this list we can have multiple pods for a single node if we are in the middle of an update.
			// one of them should have the list of policies, so we put nil only there are no entries.
			if _, exists := nodesInfo[pod.Spec.NodeName]; !exists {
				nodesInfo[pod.Spec.NodeName] = nodeInfo{
					policies: nil,
					issue: v1alpha1.NodeIssue{
						Code:    v1alpha1.NodeIssuePodNotReady,
						Message: fmt.Sprintf("pod: %s is not ready, phase: %s", pod.Name, pod.Status.Phase),
					},
				}
			}
			continue
		}

		// by default success state
		nodeIssue := v1alpha1.NodeIssue{
			Code:    v1alpha1.NodeIssueNone,
			Message: "",
		}
		policies, err := r.getPodPoliciesStatus(ctx, &pod)
		if err != nil {
			r.logger.Error(err, "failed to get pod policies status", "pod", pod.Name)
			nodeIssue = v1alpha1.NodeIssue{
				Code:    v1alpha1.NodeIssueMissingPolicy,
				Message: fmt.Sprintf("cannot list node policies: %v", err),
			}
		}

		if len(policies) == 0 {
			// if there are no policies for this pod we have an error because in previous steps
			// we checked that we have policies deployed in the cluster.
			r.logger.Error(errors.New("empty policy list"), "No policies found", "pod", pod.Name)
			nodeIssue = v1alpha1.NodeIssue{
				Code:    v1alpha1.NodeIssueMissingPolicy,
				Message: "empty policy list",
			}
		}
		nodesInfo[pod.Spec.NodeName] = nodeInfo{
			policies: policies,
			issue:    nodeIssue,
		}
	}

	// Scrape violations from each agent and group by policy namespaced name.
	violationsByPolicy := make(map[types.NamespacedName][]v1alpha1.ViolationRecord)
	for nodeName, info := range nodesInfo {
		if info.issue.Code != v1alpha1.NodeIssueNone {
			continue
		}
		agentClient, ok := r.conns[nodeName]
		if !ok {
			continue
		}
		pbViolations, err := agentClient.scrapeViolations(ctx)
		if err != nil {
			r.logger.Error(err, "failed to scrape violations", "node", nodeName)
			continue
		}
		for _, v := range pbViolations {
			nn := parsePolicyNamespacedName(v.GetPolicyName())
			rec := v1alpha1.ViolationRecord{
				Timestamp:      metav1.NewTime(v.GetTimestamp().AsTime()),
				PodName:        v.GetPodName(),
				ContainerName:  v.GetContainerName(),
				ExecutablePath: v.GetExecutablePath(),
				NodeName:       v.GetNodeName(),
				Action:         v.GetAction(),
				Count:          int32(v.GetCount()),
			}
			violationsByPolicy[nn] = append(violationsByPolicy[nn], rec)
		}
	}

	// Now we iterate over all WSPs and update their status based on the collected policies status from the agents
	for _, wp := range wpList.Items {
		nn := types.NamespacedName{Namespace: wp.Namespace, Name: wp.Name}
		err := r.processWorkloadPolicy(ctx, &wp, nodesInfo, violationsByPolicy[nn])
		if err != nil {
			r.logger.Error(
				err,
				"failed to process workload policy",
				"policy", wp.NamespacedName(),
			)
		}
	}

	return nil
}

// parsePolicyNamespacedName parses a "namespace/name" string into a NamespacedName.
func parsePolicyNamespacedName(s string) types.NamespacedName {
	parts := strings.SplitN(s, "/", 2) //nolint:mnd // namespace/name has 2 parts
	if len(parts) == 2 {                //nolint:mnd // namespace/name has 2 parts
		return types.NamespacedName{Namespace: parts[0], Name: parts[1]}
	}
	return types.NamespacedName{Name: s}
}
