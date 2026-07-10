package v1alpha1

import (
	"slices"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const MaxViolationRecords = 100

// ViolationRecord holds the details of a single policy violation.
type ViolationRecord struct {
	// id is a per-policy unique identifier allocated by the controller
	// when the record is first observed. It is stable across re-scrapes
	// of the same logical violation, so consumers can refer to a single
	// record by id (for example when correlating with external events).
	//
	// Stored as int64 (not uint64) for compatibility with the Kubernetes
	// field-management machinery used by controller-runtime's test
	// fixtures; the counter is monotonically increasing and never goes
	// negative, so the sign bit is never set in practice.
	ID int64 `json:"id"`
	// timestamp is when the violation last occurred.
	Timestamp metav1.Time `json:"timestamp"`
	// podName is the name of the pod where the violation occurred.
	PodName string `json:"podName"`
	// containerName is the container where the unauthorized executable ran.
	ContainerName string `json:"containerName"`
	// executablePath is the path of the unauthorized executable.
	ExecutablePath string `json:"executablePath"`
	// nodeName is the node where the violation occurred.
	NodeName string `json:"nodeName"`
	// action is the enforcement action taken (monitor or protect).
	Action string `json:"action"`
	// workloadName is the name of the workload that owns the pod, taken
	// from the pod's first owner reference at the time the record was
	// first observed. Empty if the pod has no owner reference or could
	// not be looked up.
	WorkloadName string `json:"workloadName,omitempty"`
	// workloadKind is the kind of the workload that owns the pod, taken
	// from the pod's first owner reference at the time the record was
	// first observed. Empty if the pod has no owner reference or could
	// not be looked up.
	WorkloadKind string `json:"workloadKind,omitempty"`
}

type AcknowledgedViolationRecord struct {
	// violation is the violation record acknowledged by users
	Violation ViolationRecord `json:"violation,omitempty"`

	// reason is an optional field to indicate the reason this violation is acknowledged.
	// +optional
	Reason string `json:"reason,omitempty"`

	// acknowledgedAt is the time when the violation was acknowledged
	AcknowledgedAt metav1.Time `json:"acknowledgedAt,omitempty"`
}

// violationRecordKey is the in-memory dedup key used to recognize the same
// logical violation across scrapes.
type violationRecordKey struct {
	podName        string
	containerName  string
	executablePath string
	action         string
}

func (r ViolationRecord) key() violationRecordKey {
	return violationRecordKey{
		podName:        r.PodName,
		containerName:  r.ContainerName,
		executablePath: r.ExecutablePath,
		action:         r.Action,
	}
}

func (wp *WorkloadPolicy) ClearAllowed() {
	wp.Status.Violations = slices.DeleteFunc(wp.Status.Violations, func(v ViolationRecord) bool {
		rules := wp.Spec.RulesByContainer[v.ContainerName]
		return rules != nil && slices.Contains(rules.Executables.Allowed, v.ExecutablePath)
	})
}

// MergeScrapedViolations dedupes scraped violations against the existing list, allocate ids for
// new records and refresh the timestamp/node on matched records.
func (s *WorkloadPolicyStatus) MergeScrapedViolations(scraped []ViolationRecord) {
	indexByKey := make(map[violationRecordKey]int, len(s.Violations))
	for i, r := range s.Violations {
		indexByKey[r.key()] = i
	}

	for _, v := range scraped {
		key := v.key()
		if idx, ok := indexByKey[key]; ok {
			// We need to overwrite the timestamp only if it is newer.
			// if in a same batch we have multiple occurrences of the violation
			// we just need to store the one with the highest timestamp.
			if v.Timestamp.Time.After(s.Violations[idx].Timestamp.Time) {
				s.Violations[idx].Timestamp = v.Timestamp
			}
		} else {
			v.ID = s.ViolationCount
			s.Violations = append(s.Violations, v)
			indexByKey[key] = len(s.Violations) - 1
		}
		s.ViolationCount++
	}

	slices.SortStableFunc(s.Violations, func(a, b ViolationRecord) int {
		return b.Timestamp.Time.Compare(a.Timestamp.Time)
	})

	if len(s.Violations) > MaxViolationRecords {
		s.Violations = s.Violations[:MaxViolationRecords]
	}
}

func (wp *WorkloadPolicy) AcknowledgeViolationsFromAnnotations(now metav1.Time) []AcknowledgedViolationRecord {
	annotations := wp.GetAnnotations()
	// No annotations -> no violations to acknowledge
	if len(annotations) == 0 {
		return nil
	}

	type annotationInfo struct {
		annotationKey string
		reason        string
	}

	acknowledges := make(map[int64]annotationInfo, len(annotations))

	for k, reason := range annotations {
		idStr, found := strings.CutPrefix(k, ViolationAcknowledgePrefix)
		if !found {
			continue
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		// we could add a validating webhook that validates the annotation format and
		// that a corresponding violation with that ID exists.
		// For now we simplify ignore the annotation if there is no a int after the prefix
		// and we will leave the annotation untouched.
		if err != nil {
			continue
		}

		acknowledges[id] = annotationInfo{
			annotationKey: k,
			reason:        reason,
		}
	}

	if len(acknowledges) == 0 {
		return nil
	}

	if wp.Status.AcknowledgedViolations == nil {
		wp.Status.AcknowledgedViolations = make([]AcknowledgedViolationRecord, 0)
	}

	ackToReturn := make([]AcknowledgedViolationRecord, 0)

	wp.Status.Violations = slices.DeleteFunc(wp.Status.Violations, func(v ViolationRecord) bool {
		info, ok := acknowledges[v.ID]
		if !ok {
			return false
		}
		// we remove the annotation from the resource
		delete(annotations, info.annotationKey)

		newAcknowledgement := AcknowledgedViolationRecord{
			Violation:      v,
			Reason:         info.reason,
			AcknowledgedAt: now,
		}
		ackToReturn = append(ackToReturn, newAcknowledgement)
		wp.Status.AcknowledgedViolations = append(wp.Status.AcknowledgedViolations, newAcknowledgement)
		return true
	})

	// we order them so that we always truncate the oldest.
	slices.SortStableFunc(wp.Status.AcknowledgedViolations, func(a, b AcknowledgedViolationRecord) int {
		return b.AcknowledgedAt.Time.Compare(a.AcknowledgedAt.Time)
	})

	if len(wp.Status.AcknowledgedViolations) > MaxViolationRecords {
		wp.Status.AcknowledgedViolations = wp.Status.AcknowledgedViolations[:MaxViolationRecords]
	}
	return ackToReturn
}
