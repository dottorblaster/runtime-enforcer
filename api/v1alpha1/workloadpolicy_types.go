package v1alpha1

import (
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// WorkloadPolicyFinalizer is added to WorkloadPolicy resources to ensure
	// they are not deleted while still in use by Pods.
	WorkloadPolicyFinalizer = "workloadpolicy.security.rancher.io/finalizer"

	// MaxNodesWithIssues is the maximum number of nodes with issues to report.
	// we don't want to overwhelm the user with too much information.
	MaxNodesWithIssues = 20
	// MaxTransitioningNodes is the maximum number of nodes transitioning to report.
	MaxTransitioningNodes = 20
)

// Phase represents the current phase of the workload policy.
type Phase string

const (
	// Transitioning indicates that the policy is in the process of changing its enforcement mode.
	Transitioning Phase = "Transitioning"
	// Failed indicates that the policy deployment has failed.
	Failed Phase = "Failed"
	// Active indicates that the policy is active.
	Active Phase = "Active"
)

type WorkloadPolicyExecutables struct {
	// allowed defines a list of executables that are allowed to run
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
	// timestamp is when the violation occurred.
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
	// count is the number of times this violation was observed (deduplicated).
	Count int32 `json:"count"`
}

// ViolationStatus holds recent violation records for a WorkloadPolicy.
type ViolationStatus struct {
	// violations is the list of the most recent violation records (max 100).
	// Oldest entries are dropped when the limit is reached.
	Violations []ViolationRecord `json:"violations,omitempty"`
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
	// violations holds recent violation records for the policy.
	// +optional
	Violations *ViolationStatus `json:"violations,omitempty"`
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
	sort.Slice(s.NodesTransitioning, func(i, j int) bool {
		return s.NodesTransitioning[i] < s.NodesTransitioning[j]
	})
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

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadPolicyList contains a list of WorkloadPolicy.
type WorkloadPolicyList struct {
	metav1.TypeMeta `json:",inline"`

	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WorkloadPolicy `json:"items"`
}

//nolint:gochecknoinits // Generated by kubebuilder
func init() {
	SchemeBuilder.Register(&WorkloadPolicy{}, &WorkloadPolicyList{})
}
