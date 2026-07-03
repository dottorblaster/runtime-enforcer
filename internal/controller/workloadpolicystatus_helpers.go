package controller

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/loglevel"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func convertToPolicyMode(mode string) pb.PolicyMode {
	switch mode {
	case policymode.ProtectString:
		return pb.PolicyMode_POLICY_MODE_PROTECT
	case policymode.MonitorString:
		return pb.PolicyMode_POLICY_MODE_MONITOR
	default:
		panic(fmt.Sprintf("unhandled policy mode: %v", mode))
	}
}

func processNodeStatus(
	status *v1alpha1.WorkloadPolicyStatus,
	nodesInfo nodesInfoMap,
	expectedMode pb.PolicyMode,
	wpNamespacedName string,
) error {
	// reset related fields
	status.NodesWithIssues = nil
	status.TotalNodes = len(nodesInfo)
	status.SuccessfulNodes = 0
	status.FailedNodes = 0
	status.TransitioningNodes = 0
	status.NodesTransitioning = nil

	for nodeName, nodeInfo := range nodesInfo {
		// If we previously detected that the policy is not deployed on this node, we can skip it.
		if nodeInfo.issue.Code != v1alpha1.NodeIssueNone {
			status.AddNodeIssue(nodeName, nodeInfo.issue)
			continue
		}

		policies := nodeInfo.policies
		if len(policies) == 0 {
			// This should be impossible since we check policies != 0 in the sync method before calling this one.
			return fmt.Errorf("no policies found for node '%s'", nodeName)
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
			return fmt.Errorf("unknown policy state '%s' for node '%s'",
				policyStatus.GetState().String(), nodeName)
		}
	}

	if status.TotalNodes != status.FailedNodes+status.TransitioningNodes+status.SuccessfulNodes {
		return fmt.Errorf("inconsistent node stats, total: %d != successful(%d)+transitioning(%d)+failed(%d)",
			status.TotalNodes, status.SuccessfulNodes, status.TransitioningNodes, status.FailedNodes)
	}

	status.SortTransitioningNodes()

	switch {
	case status.SuccessfulNodes == status.TotalNodes:
		status.Phase = v1alpha1.Ready
	case status.FailedNodes > 0:
		status.Phase = v1alpha1.Failed
	case status.TransitioningNodes > 0:
		status.Phase = v1alpha1.Transitioning
	}
	return nil
}

func (r *WorkloadPolicyStatusSync) processPolicyStatus(
	wp *v1alpha1.WorkloadPolicy,
	nodesInfo nodesInfoMap,
	scrapedViolations []v1alpha1.ViolationRecord,
) error {
	// This has to be called before considering new scraped violations, so we won't acknowledge future violations.
	err := r.processAcknowledgement(wp.Annotations, &wp.Status)
	if err != nil {
		return fmt.Errorf(
			"failed to process acknowledgement for policy %s: %w",
			wp.NamespacedName(),
			err,
		)
	}

	err = processNodeStatus(&wp.Status, nodesInfo, convertToPolicyMode(wp.Spec.Mode), wp.NamespacedName())
	if err != nil {
		return fmt.Errorf(
			"failed to compute node status for policy %s: %w",
			wp.NamespacedName(),
			err,
		)
	}
	wp.Status.ObservedGeneration = wp.Generation

	existingViolations := wp.ClearAllowed()

	// Dedupe scraped violations against the existing list, allocate ids for
	// new records (workload name/kind are already populated by the agent),
	// and refresh the timestamp/node on matched records. The returned int64
	// is the updated ViolationCount, which doubles as the id allocator (the
	// most recently allocated id is always equal to ViolationCount).
	wp.Status.Violations, wp.Status.ViolationCount = resolveScrapedViolations(
		existingViolations,
		scrapedViolations,
		wp.Status.ViolationCount,
	)

	wp.Status.ActiveViolationCount = len(wp.Status.Violations)

	return nil
}

// processAcknowledgement handles the acknowledge annotations, remove the annotations in place, and return the updated status.
//
//nolint:unparam // keep returning error for code consistency
func (r *WorkloadPolicyStatusSync) processAcknowledgement(
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
	nodesInfo nodesInfoMap,
	scrapedViolations []v1alpha1.ViolationRecord,
) error {
	patchBase := client.MergeFrom(wp.DeepCopy())
	newPolicy := wp.DeepCopy()

	err := r.processPolicyStatus(newPolicy, nodesInfo, scrapedViolations)
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

// violationRecordKey is the in-memory dedup key used to recognize the same
// logical violation across scrapes. The policy is fixed per reconcile, so
// the remaining fields are what makes a record unique. This is the same key
// the agent's in-memory buffer naturally keys on (policy, pod, container,
// executable, action); the node is intentionally excluded so a violation
// re-observed on a different node is still the same record.
type violationRecordKey struct {
	podName        string
	containerName  string
	executablePath string
	action         string
}

func violationRecordKeyOf(r v1alpha1.ViolationRecord) violationRecordKey {
	return violationRecordKey{
		podName:        r.PodName,
		containerName:  r.ContainerName,
		executablePath: r.ExecutablePath,
		action:         r.Action,
	}
}

// resolveScrapedViolations merges scraped records into existing, deduping by
// key, allocating monotonically increasing ids, and sorting by timestamp.
func resolveScrapedViolations(
	existing []v1alpha1.ViolationRecord,
	scraped []v1alpha1.ViolationRecord,
	nextViolationID int64,
) ([]v1alpha1.ViolationRecord, int64) {
	indexByKey := make(map[violationRecordKey]int, len(existing))
	for i, r := range existing {
		indexByKey[violationRecordKeyOf(r)] = i
	}

	for _, s := range scraped {
		key := violationRecordKeyOf(s)
		if idx, ok := indexByKey[key]; ok {
			// Same logical record.
			existing[idx].Timestamp = s.Timestamp
		} else {
			// Brand-new record.
			s.ID = nextViolationID
			existing = append(existing, s)
			indexByKey[key] = len(existing) - 1
		}
		nextViolationID++
	}

	slices.SortStableFunc(existing, func(a, b v1alpha1.ViolationRecord) int {
		return b.Timestamp.Time.Compare(a.Timestamp.Time)
	})

	// Trim tail (oldest entries) to keep the most recent MaxViolationRecords.
	if len(existing) > v1alpha1.MaxViolationRecords {
		existing = existing[:v1alpha1.MaxViolationRecords]
	}

	return existing, nextViolationID
}
