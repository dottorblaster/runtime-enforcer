package v1alpha1

import (
	"fmt"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// maxNodesWithIssues is the maximum number of nodes with issues to report.
	// we don't want to overwhelm the user with too much information.
	maxNodesWithIssues = 20
	// maxTransitioningNodes is the maximum number of nodes transitioning to report.
	maxTransitioningNodes = 20

	truncationString  = "..."
	truncationMessage = "Maximum number of nodes with issues reached"
)

// PolicyCode represents the status code of a policy on a node.
type PolicyCode string

const (
	PolicyUnknown       PolicyCode = ""
	PolicyReady         PolicyCode = "Ready"
	PolicyMissing       PolicyCode = "Missing"
	PolicyFailed        PolicyCode = "Failed"
	PolicyTransitioning PolicyCode = "Transitioning"
)

// PolicyStatus represents information about a policy status on a node.
type PolicyStatus struct {
	// code is the policy code.
	Code PolicyCode `json:"code,omitempty"`
	// message is a human-readable description.
	Message string `json:"message,omitempty"`
	// since is the time at which the node entered its current status.
	// It is stamped by the controller when the node's code changes and
	// preserved across status recomputations while the code is unchanged;
	// the agent does not report it.
	// +optional
	Since metav1.Time `json:"since,omitempty"`
}

type PolicyNodeStatus struct {
	PolicyStatus `json:",inline"`

	NodeName string `json:"nodeName,omitempty"`
}

func (s *WorkloadPolicyStatus) addTransitioningNode(status PolicyNodeStatus, previous PolicyStatus, now time.Time) {
	// we always increment the transitioning count
	s.TransitioningNodes++

	if s.NodesTransitioning == nil {
		s.NodesTransitioning = make([]PolicyNodeStatus, 0, maxTransitioningNodes)
	}

	// we store up to maxTransitioningNodes-1, the last element will be a marker of max reached
	if len(s.NodesTransitioning) < maxTransitioningNodes-1 {
		status.Since = transitionTime(previous, status.PolicyStatus, now)
		s.NodesTransitioning = append(s.NodesTransitioning, status)
	} else if len(s.NodesTransitioning) == maxTransitioningNodes-1 {
		s.NodesTransitioning = append(s.NodesTransitioning, PolicyNodeStatus{NodeName: truncationString})
	}
}

func (s *WorkloadPolicyStatus) addNodeIssue(
	nodeName string,
	status PolicyStatus,
	previous PolicyStatus,
	now time.Time,
) {
	// we always increment the failure count
	s.FailedNodes++

	if s.NodesWithIssues == nil {
		s.NodesWithIssues = make(map[string]PolicyStatus, maxNodesWithIssues)
	}

	// we store up to maxNodesWithIssues-1, the last element will be a marker of max reached
	if len(s.NodesWithIssues) < maxNodesWithIssues-1 {
		status.Since = transitionTime(previous, status, now)
		s.NodesWithIssues[nodeName] = status
	} else if len(s.NodesWithIssues) == maxNodesWithIssues-1 {
		s.NodesWithIssues[truncationString] = PolicyStatus{
			Code:    PolicyFailed,
			Message: truncationMessage,
		}
	}
}

// transitionTime returns the time at which a node entered its current status.
// If the node's code is unchanged from the previous status and a timestamp is
// already known, it is carried forward; otherwise the current time is stamped.
// The latter also covers the first observation after an upgrade, when the
// previous status predates the "since" field and carries a zero timestamp.
func transitionTime(previous, current PolicyStatus, now time.Time) metav1.Time {
	if previous.Code == current.Code && !previous.Since.Time.IsZero() {
		return previous.Since
	}
	return metav1.Time{Time: now}
}

func (s *WorkloadPolicyStatus) resetPolicyNodeStatus(totalNodes int) {
	s.NodesWithIssues = nil
	s.NodesTransitioning = nil
	s.TotalNodes = totalNodes
	s.SuccessfulNodes = 0
	s.FailedNodes = 0
	s.TransitioningNodes = 0
}

// nodeStatus returns the previous status of a node, if any. A zero-value
// PolicyStatus is returned when the node has no prior record, for example
// because it was previously ready and ready nodes are not tracked by name.
func (s WorkloadPolicyStatus) nodeStatus(nodeName string) PolicyStatus {
	if ps, ok := s.NodesWithIssues[nodeName]; ok {
		return ps
	}
	for _, ns := range s.NodesTransitioning {
		if ns.NodeName == nodeName {
			return ns.PolicyStatus
		}
	}
	return PolicyStatus{}
}

// processPolicyNodeStatus recomputes the per-node status counters and maps.
// previous is the status carried by the object before this recomputation; it
// is used to preserve the per-node "since" timestamp across recomputations
// when a node's code is unchanged (see transitionTime). now is the time
// stamped when a node enters a new code.
func (s *WorkloadPolicyStatus) processPolicyNodeStatus(
	previous WorkloadPolicyStatus,
	nodes []PolicyNodeStatus,
	now time.Time,
) error {
	s.resetPolicyNodeStatus(len(nodes))

	for _, status := range nodes {
		switch status.Code {
		case PolicyReady:
			s.SuccessfulNodes++
		case PolicyTransitioning:
			s.addTransitioningNode(status, previous.nodeStatus(status.NodeName), now)
		case PolicyFailed, PolicyMissing:
			s.addNodeIssue(
				status.NodeName,
				PolicyStatus{Code: status.Code, Message: status.Message},
				previous.nodeStatus(status.NodeName),
				now,
			)
		case PolicyUnknown:
			fallthrough
		default:
			return fmt.Errorf("unknown node status state %q for node %q", status.Code, status.NodeName)
		}
	}

	// We order the slice to avoid resource status updates in case of different order
	if len(s.NodesTransitioning) > 0 {
		slices.SortFunc(s.NodesTransitioning, func(a, b PolicyNodeStatus) int {
			return strings.Compare(a.NodeName, b.NodeName)
		})
	}

	// Consistency check
	if s.TotalNodes != s.FailedNodes+s.TransitioningNodes+s.SuccessfulNodes {
		return fmt.Errorf("inconsistent node stats, total: %d != successful(%d)+transitioning(%d)+failed(%d)",
			s.TotalNodes, s.SuccessfulNodes, s.TransitioningNodes, s.FailedNodes)
	}

	switch {
	case s.SuccessfulNodes == s.TotalNodes:
		s.Phase = Ready
	case s.FailedNodes > 0:
		s.Phase = Failed
	case s.TransitioningNodes > 0:
		s.Phase = Transitioning
	}

	return nil
}
