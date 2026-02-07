package controller

import (
	"context"
	"fmt"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

func isPodReady(pod *corev1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// gcStaleConnections cleanup stale connections so that we don't indefinitely grow the connection map in case of failures.
func (r *WorkloadPolicyStatusSync) gcStaleConnections(podList *corev1.PodList) {
	activeNodes := sets.New[string]()
	for _, pod := range podList.Items {
		activeNodes.Insert(pod.Spec.NodeName)
	}

	for nodeName, c := range r.conns {
		if activeNodes.Has(nodeName) {
			continue
		}
		_ = c.close()
		delete(r.conns, nodeName)
	}
}

func (r *WorkloadPolicyStatusSync) getPodPoliciesStatus(
	ctx context.Context,
	pod *corev1.Pod,
) (map[string]*pb.PolicyStatus, error) {
	// Check if we need to create a new connection or reuse an existing one
	agentClient, ok := r.conns[pod.Spec.NodeName]
	if !ok {
		c, err := r.agentClientFactory.newClient(pod.Status.PodIP, pod.Name, pod.Namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to create connection to pod %s: %w", pod.Name, err)
		}
		r.conns[pod.Spec.NodeName] = c
		agentClient = c
	}

	resp, err := agentClient.listPoliciesStatus(ctx)
	if err != nil {
		// in case of error we close the connection and we will open a new one at the next sync
		_ = agentClient.close()
		delete(r.conns, pod.Spec.NodeName)
		return nil, fmt.Errorf("failed to list policies status for pod %s: %w", pod.Name, err)
	}
	return resp, nil
}

func convertToPolicyMode(mode string) pb.PolicyMode {
	switch mode {
	case "protect":
		return pb.PolicyMode_POLICY_MODE_PROTECT
	case "monitor":
		return pb.PolicyMode_POLICY_MODE_MONITOR
	default:
		panic(fmt.Sprintf("unhandled policy mode: %v", mode))
	}
}

func computeWpStatus(
	nodesInfo nodesInfoMap,
	expectedMode pb.PolicyMode,
	wpNamespacedName string,
) (v1alpha1.WorkloadPolicyStatus, error) {
	status := v1alpha1.WorkloadPolicyStatus{
		TotalNodes: len(nodesInfo),
	}

	for nodeName, nodeInfo := range nodesInfo {
		// If we previously detected that the policy is not deployed on this node, we can skip it.
		if nodeInfo.issue.Code != v1alpha1.NodeIssueNone {
			status.AddNodeIssue(nodeName, nodeInfo.issue)
			continue
		}

		policies := nodeInfo.policies
		if len(policies) == 0 {
			// This should be impossible since we check policies != 0 in the sync method before calling this one.
			return v1alpha1.WorkloadPolicyStatus{}, fmt.Errorf("no policies found for node '%s'", nodeName)
		}

		policyStatus, ok := policies[wpNamespacedName]
		if !ok || policyStatus == nil {
			status.AddNodeIssue(nodeName, v1alpha1.NodeIssue{
				Code:    v1alpha1.NodeIssueMissingPolicy,
				Message: "policy not present on the node",
			})
			continue
		}

		switch policyStatus.GetState() {
		case pb.PolicyState_POLICY_STATE_READY:
			if policyStatus.GetMode() == expectedMode {
				status.SuccessfulNodes++
				break
			}
			status.AddTransitioningNode(nodeName)
		case pb.PolicyState_POLICY_STATE_ERROR:
			status.AddNodeIssue(nodeName, v1alpha1.NodeIssue{
				Code: v1alpha1.NodeIssuePolicyFailed,
				// todo!: we should receive the error message from the agent.
				Message: "policy is in error state",
			})
		case pb.PolicyState_POLICY_STATE_UNSPECIFIED:
		default:
			return v1alpha1.WorkloadPolicyStatus{}, fmt.Errorf("unknown policy state '%s' for node '%s'",
				policyStatus.GetState().String(), nodeName)
		}
	}

	if status.TotalNodes != status.FailedNodes+status.TransitioningNodes+status.SuccessfulNodes {
		return v1alpha1.WorkloadPolicyStatus{},
			fmt.Errorf("inconsistent node stats, total: %d != successful(%d)+transitioning(%d)+failed(%d)",
				status.TotalNodes, status.SuccessfulNodes, status.TransitioningNodes, status.FailedNodes)
	}

	status.SortTransitioningNodes()

	switch {
	case status.SuccessfulNodes == status.TotalNodes:
		status.Phase = v1alpha1.Active
	case status.FailedNodes > 0:
		status.Phase = v1alpha1.Failed
	case status.TransitioningNodes > 0:
		status.Phase = v1alpha1.Transitioning
	}
	return status, nil
}

func (r *WorkloadPolicyStatusSync) processWorkloadPolicy(
	ctx context.Context,
	wp *v1alpha1.WorkloadPolicy,
	nodesInfo nodesInfoMap,
) error {
	expectedMode := convertToPolicyMode(wp.Spec.Mode)
	newPolicy := wp.DeepCopy()
	var err error
	if newPolicy.Status, err = computeWpStatus(nodesInfo, expectedMode, newPolicy.NamespacedName()); err != nil {
		return fmt.Errorf("failed to compute status for policy %s: %w", newPolicy.NamespacedName(), err)
	}
	newPolicy.Status.ObservedGeneration = wp.Generation
	// Preserve the violation counters set by the agent's ViolationReporter.
	newPolicy.Status.Violations = wp.Status.Violations
	r.logger.V(1).Info("updating",
		"policy", newPolicy.NamespacedName(),
		"status:", newPolicy.Status)
	return r.Status().Update(ctx, newPolicy)
}
