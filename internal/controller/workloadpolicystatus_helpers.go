package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/loglevel"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *WorkloadPolicyStatusSync) processPolicyStatus(
	ctx context.Context,
	wp *v1alpha1.WorkloadPolicy,
	nodes []v1alpha1.PolicyNodeStatus,
	scrapedViolations []v1alpha1.ViolationRecord,
) error {
	if err := wp.Status.ProcessPolicyNodeStatus(nodes); err != nil {
		return fmt.Errorf(
			"failed to compute node status for policy %s: %w",
			wp.NamespacedName(),
			err,
		)
	}

	// Merge scraped violations into the status.
	// we will clear/acknowledge violations after the merge so that the status
	// is coherent across syncs.
	wp.Status.MergeScrapedViolations(scrapedViolations)

	wp.ClearAllowed()

	// This has to be called before considering new scraped violations, so we won't acknowledge future violations.
	err := r.processAcknowledgement(ctx, wp.Annotations, &wp.Status)
	if err != nil {
		return fmt.Errorf(
			"failed to process acknowledgement for policy %s: %w",
			wp.NamespacedName(),
			err,
		)
	}

	wp.Status.ActiveViolationCount = len(wp.Status.Violations)
	wp.Status.ObservedGeneration = wp.Generation

	return nil
}

// processAcknowledgement handles the acknowledge annotations, remove the annotations in place, and return the updated status.
//
//nolint:unparam // keep returning error for code consistency
func (r *WorkloadPolicyStatusSync) processAcknowledgement(
	ctx context.Context,
	annotations map[string]string,
	status *v1alpha1.WorkloadPolicyStatus,
) error {
	acknowledges := make(map[int64]string, len(annotations))

	// Find all valid annotations.
	for k, v := range annotations {
		if idStr, found := strings.CutPrefix(k, v1alpha1.ViolationAcknowledgePrefix); found {
			delete(annotations, k)
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				r.logger.Error(err, "failed to convert acknowledge id",
					"annotation", k,
				)
				continue
			}
			acknowledges[id] = v
		}
	}

	// Filter status.Violations
	violationResult := make([]v1alpha1.ViolationRecord, 0, len(status.Violations))
	for _, violation := range status.Violations {
		if reason, found := acknowledges[violation.ID]; found {
			status.AcknowledgedViolations = append(
				status.AcknowledgedViolations,
				v1alpha1.AcknowledgedViolationRecord{
					Violation:      violation,
					Reason:         reason,
					AcknowledgedAt: metav1.NewTime(time.Now()),
				},
			)
			delete(acknowledges, violation.ID)
			r.emitAcknowledgedViolationOtelLog(ctx, violation, reason)
		} else {
			violationResult = append(violationResult, violation)
		}
	}
	status.Violations = violationResult

	if len(acknowledges) > 0 {
		r.logger.Info("no matching violations for ID in acknowledgements",
			"acknowledges", acknowledges,
		)
	}

	// Trim front (oldest entries) to keep the most recent MaxViolationRecords.
	if len(status.AcknowledgedViolations) > v1alpha1.MaxViolationRecords {
		status.AcknowledgedViolations = status.AcknowledgedViolations[len(status.AcknowledgedViolations)-v1alpha1.MaxViolationRecords:]
	}
	return nil
}

// processWorkloadPolicy updates the wp.status and wp.annotation in order to acknowledge a violation.
// NOTE: agent side ignores annotation changes and status change via predicate.GenerationChangedPredicate{}.
func (r *WorkloadPolicyStatusSync) processWorkloadPolicy(
	ctx context.Context,
	wp *v1alpha1.WorkloadPolicy,
	nodes []v1alpha1.PolicyNodeStatus,
	scrapedViolations []v1alpha1.ViolationRecord,
) error {
	patchBase := client.MergeFrom(wp.DeepCopy())
	newPolicy := wp.DeepCopy()

	err := r.processPolicyStatus(ctx, newPolicy, nodes, scrapedViolations)
	if err != nil {
		return err
	}

	r.logger.V(loglevel.VerbosityDebug).Info("updating",
		"policy", newPolicy.NamespacedName(),
		"annotations", newPolicy.Annotations,
		"status", newPolicy.Status)

	// At this point, we already have the expected WorkloadPolicy.
	// Due to kubernetes design, we have to call update annotations and status separately.
	// Here we use Patch() to prevent annotation changes made between two calls from being lost.

	// We update status first and remove the annotations later
	// If anything goes wrong we can retry in the next reconcile.
	err = r.Status().Patch(ctx, newPolicy.DeepCopy(), patchBase)
	if err != nil {
		return err
	}

	err = r.Patch(ctx, newPolicy.DeepCopy(), patchBase)
	if err != nil {
		return err
	}
	return nil
}

func storeStatusForEachPolicy(
	nodeStatusByPolicy map[string][]v1alpha1.PolicyNodeStatus,
	policies []v1alpha1.WorkloadPolicy,
	nodeStatus v1alpha1.PolicyNodeStatus,
) {
	// Store the node status for the given policy
	for _, policy := range policies {
		policyNamespacedName := policy.NamespacedName()
		nodeStatusByPolicy[policyNamespacedName] = append(
			nodeStatusByPolicy[policyNamespacedName],
			nodeStatus,
		)
	}
}

func (r *WorkloadPolicyStatusSync) getNodeStatusByPolicy(
	ctx context.Context,
	clients map[string]grpcexporter.AgentClientAPI,
	policies []v1alpha1.WorkloadPolicy,
) map[string][]v1alpha1.PolicyNodeStatus {
	nodeStatusByPolicy := make(map[string][]v1alpha1.PolicyNodeStatus, len(policies))
	for _, policy := range policies {
		nodeStatusByPolicy[policy.NamespacedName()] = make([]v1alpha1.PolicyNodeStatus, 0, len(clients))
	}

	for nodeName, client := range clients {
		if client == nil {
			r.logger.Info("cannot get a agent client for the node", "node", nodeName)
			storeStatusForEachPolicy(nodeStatusByPolicy, policies, v1alpha1.PolicyNodeStatus{
				NodeName: nodeName,
				PolicyStatus: v1alpha1.PolicyStatus{
					Code:    v1alpha1.PolicyMissing,
					Message: "No agent client available",
				},
			})
			continue
		}

		nodePolicies, err := client.ListPoliciesStatus(ctx)
		if err != nil {
			r.agentClientPool.MarkStaleAgentClient(nodeName)
			r.logger.Error(err, "failed to get policies status", "node", nodeName)
			storeStatusForEachPolicy(nodeStatusByPolicy, policies, v1alpha1.PolicyNodeStatus{
				NodeName: nodeName,
				PolicyStatus: v1alpha1.PolicyStatus{
					Code:    v1alpha1.PolicyMissing,
					Message: "failed to get policies status",
				},
			})
			continue
		}

		if len(nodePolicies) == 0 {
			r.logger.Error(errors.New("empty policy list"), "No policies found", "node", nodeName)
			storeStatusForEachPolicy(nodeStatusByPolicy, policies, v1alpha1.PolicyNodeStatus{
				NodeName: nodeName,
				PolicyStatus: v1alpha1.PolicyStatus{
					Code:    v1alpha1.PolicyMissing,
					Message: "no policies found on the node",
				},
			})
			continue
		}

		for _, policy := range policies {
			policyNamespacedName := policy.NamespacedName()
			nodeStatus := v1alpha1.PolicyNodeStatus{NodeName: nodeName}

			if nodeStatus.Code, nodeStatus.Message, err = policyNodeStatus(
				policy.Spec.Mode,
				nodePolicies[policyNamespacedName],
			); err != nil {
				r.logger.Error(
					err,
					"failed to get policy node status",
					"node",
					nodeName,
					"policy",
					policyNamespacedName,
				)
				continue
			}

			nodeStatusByPolicy[policyNamespacedName] = append(
				nodeStatusByPolicy[policyNamespacedName],
				nodeStatus,
			)
		}
	}

	return nodeStatusByPolicy
}

func policyNodeStatus(
	expectedMode string,
	policyStatus *pb.PolicyStatus,
) (v1alpha1.PolicyCode, string, error) {
	if policyStatus == nil {
		return v1alpha1.PolicyUnknown, "", errors.New("policy status is nil")
	}

	policyModeMatchesExpected := func(mode pb.PolicyMode, expectedMode string) bool {
		switch expectedMode {
		case policymode.ProtectString:
			return mode == pb.PolicyMode_POLICY_MODE_PROTECT
		case policymode.MonitorString:
			return mode == pb.PolicyMode_POLICY_MODE_MONITOR
		default:
			return false
		}
	}

	switch policyStatus.GetState() {
	case pb.PolicyState_POLICY_STATE_READY:
		if policyModeMatchesExpected(policyStatus.GetMode(), expectedMode) {
			return v1alpha1.PolicyReady, "", nil
		}
		return v1alpha1.PolicyTransitioning, "", nil
	case pb.PolicyState_POLICY_STATE_ERROR:
		msg := policyStatus.GetMessage()
		if msg == "" {
			msg = "policy is in error state"
		}
		return v1alpha1.PolicyFailed, msg, nil
	case pb.PolicyState_POLICY_STATE_UNSPECIFIED:
		fallthrough
	default:
		return v1alpha1.PolicyUnknown, "", fmt.Errorf("unknown policy state %q",
			policyStatus.GetState().String())
	}
}
