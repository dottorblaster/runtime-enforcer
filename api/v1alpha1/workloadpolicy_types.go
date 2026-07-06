package v1alpha1

import (
	"errors"
	"fmt"
	"slices"

	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	PolicyModeMonitor = policymode.MonitorString
	PolicyModeProtect = policymode.ProtectString
)

const (
	// MaxNodesWithIssues is the maximum number of nodes with issues to report.
	// we don't want to overwhelm the user with too much information.
	MaxNodesWithIssues = 20
	// MaxTransitioningNodes is the maximum number of nodes transitioning to report.
	MaxTransitioningNodes = 20
)

// Phase represents the current phase of the workload policy.
// Possible values are:
// - "Transitioning": the policy is in the process of changing its enforcement mode.
// - "Failed": the policy deployment has failed.
// - "Ready": the policy is ready and actively enforced.
type Phase string

const (
	// Transitioning indicates that the policy is in the process of changing its enforcement mode.
	Transitioning Phase = "Transitioning"
	// Failed indicates that the policy deployment has failed.
	Failed Phase = "Failed"
	// Ready indicates that the policy is ready.
	Ready Phase = "Ready"
)

type WorkloadPolicyExecutables struct {
	// allowed defines a list of executables that are allowed to run
	// +kubebuilder:validation:items:Pattern=`^/.*$`
	// +optional
	Allowed []string `json:"allowed,omitempty"`
}

type WorkloadPolicyRules struct {
	// executables defines a security policy for executables.
	// +optional
	Executables WorkloadPolicyExecutables `json:"executables,omitempty"`
}

type WorkloadPolicySpec struct {
	// mode defines the execution mode of this policy. Can be set to
	// either "protect" or "monitor". In "protect" mode, the policy
	// blocks and reports violations, while in "monitor" mode,
	// it only reports violations.
	// +kubebuilder:validation:Enum=monitor;protect
	// +kubebuilder:validation:Required
	Mode string `json:"mode,omitempty"`

	// rulesByContainer specifies for each container the list of rules to apply.
	RulesByContainer map[string]*WorkloadPolicyRules `json:"rulesByContainer,omitempty"`
}

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

type WorkloadPolicyStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// nodesWithIssues contains the status of each node with issues.
	NodesWithIssues map[string]NodeIssue `json:"nodesWithIssues,omitempty"`
	// totalNodes is the total number of nodes the policy is applied to.
	TotalNodes int `json:"totalNodes,omitempty"`
	// successfulNodes is the number of nodes where the policy is successfully enforced.
	SuccessfulNodes int `json:"successfulNodes,omitempty"`
	// failedNodes is the number of nodes where the policy enforcement failed.
	FailedNodes int `json:"failedNodes,omitempty"`
	// transitioningNodes is the number of nodes where the policy is transitioning mode.
	TransitioningNodes int `json:"transitioningNodes,omitempty"`
	// nodesTransitioning contains the names of the nodes that are transitioning.
	NodesTransitioning []string `json:"nodesTransitioning,omitempty"`
	// phase indicates the current phase of the workload policy.
	Phase Phase `json:"phase,omitempty"`
	// violationCount is the total number of unique violation records
	// ever observed for this policy, including those that have already
	// been trimmed out of Violations. It also doubles as the per-policy
	// id allocator: when a brand-new record is first added, the
	// reconciler bumps ViolationCount and stamps the new value onto the
	// record as its id, all in the same status update. As a result, the
	// largest id ever allocated for a policy is always equal to
	// ViolationCount, and re-scraped (deduped) records do not bump it.
	//
	// Note: This value is maintained by the reconciler and reflects
	// its best-effort view of the system. It is not guaranteed to be
	// strongly consistent and may be temporarily outdated depending on
	// reconciliation.
	// +optional
	ViolationCount int64 `json:"violationCount,omitempty"`
	// violations is the list of the most recent violation records (max MaxViolationRecords).
	// Oldest entries are dropped when the limit is reached.
	// +optional
	Violations []ViolationRecord `json:"violations,omitempty"`
}

func (s *WorkloadPolicyStatus) AddNodeIssue(nodeName string, issue NodeIssue) {
	// we always increment the failure count
	s.FailedNodes++

	if s.NodesWithIssues == nil {
		s.NodesWithIssues = make(map[string]NodeIssue, MaxNodesWithIssues)
	}

	// we store up to MaxNodesWithIssues-1, the last element will be a marker of max reached
	if len(s.NodesWithIssues) < MaxNodesWithIssues-1 {
		s.NodesWithIssues[nodeName] = issue
	} else if len(s.NodesWithIssues) == MaxNodesWithIssues-1 {
		s.NodesWithIssues[TruncationNodeString] = NodeIssue{
			Code:    NodeIssueMaxReached,
			Message: "Maximum number of nodes with issues reached",
		}
	}
}

func (s *WorkloadPolicyStatus) SortTransitioningNodes() {
	if len(s.NodesTransitioning) == 0 {
		return
	}

	// we sort the transitioning nodes because we don't want to trigger
	// updates on the WP if only the order of transitioning nodes has changed.
	// Note: since this list is truncated it is still possible we trigger some updates if
	// the number of transitioning nodes is greater than MaxTransitioningNodes.
	slices.Sort(s.NodesTransitioning)
}

func (s *WorkloadPolicyStatus) AddTransitioningNode(nodeName string) {
	// we always increment the transitioning count
	s.TransitioningNodes++

	if s.NodesTransitioning == nil {
		s.NodesTransitioning = make([]string, 0, MaxTransitioningNodes)
	}

	// we store up to MaxTransitioningNodes-1, the last element will be a marker of max reached
	if len(s.NodesTransitioning) < MaxTransitioningNodes-1 {
		s.NodesTransitioning = append(s.NodesTransitioning, nodeName)
	} else if len(s.NodesTransitioning) == MaxTransitioningNodes-1 {
		s.NodesTransitioning = append(s.NodesTransitioning, TruncationNodeString)
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:resource:categories={rancher-security},singular="workloadpolicy",path="workloadpolicies",scope="Namespaced",shortName={wp}
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadPolicy is the Schema for the workloadpolicies API.
type WorkloadPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkloadPolicySpec   `json:"spec,omitempty"`
	Status WorkloadPolicyStatus `json:"status,omitempty"`
}

// NamespacedName returns a string in the form "<namespace>/<name>".
//
// This is useful when storing/retrieving WorkloadPolicy-related state in maps.
func (wp *WorkloadPolicy) NamespacedName() string {
	if wp == nil {
		return ""
	}
	return wp.Namespace + "/" + wp.Name
}

func (wp *WorkloadPolicy) SetPromotedLabel(proposalName string) error {
	if wp == nil {
		return errors.New("WorkloadPolicy is nil")
	}

	// k8s labels must have 63 chars or less.
	// We catch here the error instead of letting the API server handle it.
	const maxLabelValueLength = 63
	if len(proposalName) > maxLabelValueLength {
		return fmt.Errorf("proposalName %q is too long", proposalName)
	}

	if wp.Labels == nil {
		wp.SetLabels(map[string]string{})
	}

	wp.Labels[PolicyPromotedFromLabelKey] = proposalName
	return nil
}

func (wp *WorkloadPolicy) HasPromotedLabel(proposalName string) bool {
	if wp == nil {
		return false
	}
	return wp.Labels[PolicyPromotedFromLabelKey] == proposalName
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadPolicyList contains a list of WorkloadPolicy.
type WorkloadPolicyList struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WorkloadPolicy `json:"items"`
}
