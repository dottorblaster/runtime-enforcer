package controller

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-logr/logr"
	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/loglevel"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
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
		status.Phase = v1alpha1.Ready
	case status.FailedNodes > 0:
		status.Phase = v1alpha1.Failed
	case status.TransitioningNodes > 0:
		status.Phase = v1alpha1.Transitioning
	}
	return status, nil
}

func buildPolicyStatus(
	ctx context.Context,
	c client.Client,
	log logr.Logger,
	wp *v1alpha1.WorkloadPolicy,
	nodesInfo nodesInfoMap,
	scrapedViolations []v1alpha1.ViolationRecord,
) (v1alpha1.WorkloadPolicyStatus, error) {
	newStatus, err := computeWpStatus(nodesInfo, convertToPolicyMode(wp.Spec.Mode), wp.NamespacedName())
	if err != nil {
		return v1alpha1.WorkloadPolicyStatus{}, fmt.Errorf(
			"failed to compute status for policy %s: %w",
			wp.NamespacedName(),
			err,
		)
	}
	newStatus.ObservedGeneration = wp.Generation

	// Dedupe scraped violations against the existing list, allocate ids for
	// new records, look up workload (name/kind) from the pod's first owner
	// reference, and refresh the timestamp/node on matched records. The
	// returned int64 is the updated ViolationCount, which doubles as the
	// id allocator (the most recently allocated id is always equal to
	// ViolationCount).
	merged, newCount := resolveScrapedViolations(
		ctx, c, log,
		wp.Status.Violations,
		scrapedViolations,
		wp.Status.ViolationCount,
		wp.Namespace,
	)
	newStatus.Violations = merged
	newStatus.ViolationCount = newCount
	return newStatus, nil
}

func (r *WorkloadPolicyStatusSync) processWorkloadPolicy(
	ctx context.Context,
	wp *v1alpha1.WorkloadPolicy,
	nodesInfo nodesInfoMap,
	scrapedViolations []v1alpha1.ViolationRecord,
) error {
	status, err := buildPolicyStatus(ctx, r.Client, r.logger, wp, nodesInfo, scrapedViolations)
	if err != nil {
		return err
	}
	newPolicy := wp.DeepCopy()
	newPolicy.Status = status

	r.logger.V(loglevel.VerbosityDebug).Info("updating",
		"policy", newPolicy.NamespacedName(),
		"status", newPolicy.Status)
	return r.Status().Update(ctx, newPolicy)
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

// resolveScrapedViolations dedupes scraped records against the existing list,
// allocates ids for new records, looks up the workload (name/kind) from the
// pod's first owner reference, and refreshes the timestamp/node on matched
// records. It returns the merged violations list (unmatched scraped records
// prepended, existing records in their original order with timestamps and
// nodes refreshed where matched) and the updated ViolationCount.
//
// ViolationCount doubles as the id allocator: every brand-new record is
// stamped with the post-increment value of ViolationCount, so the largest
// id ever allocated for a policy is always equal to ViolationCount and
// re-scraped (deduped) records do not bump it. A fresh policy starts at
// 0 and the first id allocated is 1.
func resolveScrapedViolations(
	ctx context.Context,
	c client.Client,
	log logr.Logger,
	existing []v1alpha1.ViolationRecord,
	scraped []v1alpha1.ViolationRecord,
	violationCount int64,
	namespace string,
) ([]v1alpha1.ViolationRecord, int64) {
	// Index existing records by their dedup key so we can recognize a
	// re-scraped record on the first try.
	indexByKey := make(map[violationRecordKey]int, len(existing))
	for i, r := range existing {
		indexByKey[violationRecordKeyOf(r)] = i
	}

	// Cache pod -> (workload name, workload kind) lookups so a re-scraped
	// record that we've already resolved this tick does not hit the API
	// server again. Misses are also cached (as empty refs) to avoid
	// hammering the API server for pods that genuinely have no owner.
	workloadCache := make(map[string]workloadRef, len(scraped))

	var newRecords []v1alpha1.ViolationRecord
	for _, s := range scraped {
		key := violationRecordKeyOf(s)
		if idx, ok := indexByKey[key]; ok {
			// Same logical record: refresh the time and node in place.
			// We keep the original id and workload fields — that is the
			// whole point of the dedup key.
			existing[idx].Timestamp = s.Timestamp
			existing[idx].NodeName = s.NodeName
			continue
		}

		// Brand-new record: bump the count, stamp the new value as the
		// record's id, and look up the pod's first owner reference to
		// populate the workload fields. The increment happens before the
		// assignment so a fresh policy (count == 0) gets id 1, not 0.
		violationCount++
		s.ID = violationCount
		name, kind := lookupWorkload(ctx, c, log, workloadCache, namespace, s.PodName)
		s.WorkloadName = name
		s.WorkloadKind = kind
		newRecords = append(newRecords, s)
	}

	// Prepend the freshly allocated records in scrape order, then keep
	// the existing list in place (with timestamps refreshed for matches).
	merged := slices.Concat(newRecords, existing)

	// Trim tail (oldest entries) to keep the most recent MaxViolationRecords.
	if len(merged) > v1alpha1.MaxViolationRecords {
		merged = merged[:v1alpha1.MaxViolationRecords]
	}

	return merged, violationCount
}

// workloadRef is the workload identity (name + kind) taken from a pod's
// first owner reference.
type workloadRef struct {
	name string
	kind string
}

// lookupWorkload returns the name and kind of the workload that owns the
// given pod, based on the pod's first owner reference. Results are cached
// in `cache` so repeated lookups in the same tick are free, and misses are
// also cached (as the zero value) to avoid retrying forever. The function
// swallows lookup errors — a missing pod or one without an owner reference
// is a legitimate end state, not a failure.
func lookupWorkload(
	ctx context.Context,
	c client.Client,
	log logr.Logger,
	cache map[string]workloadRef,
	namespace, podName string,
) (string, string) {
	if podName == "" {
		return "", ""
	}
	if ref, ok := cache[podName]; ok {
		return ref.name, ref.kind
	}
	pod := &corev1.Pod{}
	key := types.NamespacedName{Namespace: namespace, Name: podName}
	if err := c.Get(ctx, key, pod); err != nil {
		log.V(loglevel.VerbosityDebug).Info("could not look up pod for workload resolution",
			"pod", podName, "namespace", namespace, "error", err)
		cache[podName] = workloadRef{}
		return "", ""
	}
	if len(pod.OwnerReferences) == 0 {
		cache[podName] = workloadRef{}
		return "", ""
	}
	ref := workloadRef{
		name: pod.OwnerReferences[0].Name,
		kind: pod.OwnerReferences[0].Kind,
	}
	cache[podName] = ref
	return ref.name, ref.kind
}
