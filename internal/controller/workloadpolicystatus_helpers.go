package controller

import (
	"context"
	"fmt"
	"slices"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
)

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
			msg := policyStatus.GetMessage()
			if msg == "" {
				msg = "policy is in error state"
			}
			status.AddNodeIssue(nodeName, v1alpha1.NodeIssue{
				Code:    v1alpha1.NodeIssuePolicyFailed,
				Message: msg,
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
	scrapedViolations []v1alpha1.ViolationRecord,
) error {
	expectedMode := convertToPolicyMode(wp.Spec.Mode)
	newPolicy := wp.DeepCopy()
	var err error
	if newPolicy.Status, err = computeWpStatus(nodesInfo, expectedMode, newPolicy.NamespacedName()); err != nil {
		return fmt.Errorf("failed to compute status for policy %s: %w", newPolicy.NamespacedName(), err)
	}
	newPolicy.Status.ObservedGeneration = wp.Generation

	// Merge scraped violations into status: prepend new violations to existing,
	// then trim to the most recent MaxViolationRecords entries.
	newPolicy.Status.Violations = mergeViolations(wp.Status.Violations, scrapedViolations)

	r.logger.V(1).Info("updating",
		"policy", newPolicy.NamespacedName(),
		"status", newPolicy.Status)
	return r.Status().Update(ctx, newPolicy)
}

// mergeViolations prepends scraped violations to the existing list,
// trimming the tail (oldest) to keep only the most recent MaxViolationRecords.
// The resulting list is ordered newest-to-oldest.
func mergeViolations(
	existing []v1alpha1.ViolationRecord,
	scraped []v1alpha1.ViolationRecord,
) []v1alpha1.ViolationRecord {
	// Prepend scraped (newest) before existing (older) so the list is newest-to-oldest.
	merged := slices.Concat(scraped, existing)

	// Trim tail (oldest entries) to keep the most recent MaxViolationRecords.
	if len(merged) > v1alpha1.MaxViolationRecords {
		merged = merged[:v1alpha1.MaxViolationRecords]
	}

	return merged
}
