package v1alpha1

import (
	"slices"

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

func (wp *WorkloadPolicy) ClearAllowed() []ViolationRecord {
	return slices.DeleteFunc(wp.Status.Violations, func(v ViolationRecord) bool {
		rules := wp.Spec.RulesByContainer[v.ContainerName]
		return rules != nil && slices.Contains(rules.Executables.Allowed, v.ExecutablePath)
	})
}
