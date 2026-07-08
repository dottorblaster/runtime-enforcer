package v1alpha1

import (
	"fmt"
	"slices"
	"strings"
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
}

type PolicyNodeStatus struct {
	PolicyStatus

	NodeName string `json:"nodeName,omitempty"`
}

func (s *WorkloadPolicyStatus) addTransitioningNode(nodeName string) {
	// we always increment the transitioning count
	s.TransitioningNodes++

	if s.NodesTransitioning == nil {
		s.NodesTransitioning = make([]string, 0, maxTransitioningNodes)
	}

	// we store up to maxTransitioningNodes-1, the last element will be a marker of max reached
	if len(s.NodesTransitioning) < maxTransitioningNodes-1 {
		s.NodesTransitioning = append(s.NodesTransitioning, nodeName)
	} else if len(s.NodesTransitioning) == maxTransitioningNodes-1 {
		s.NodesTransitioning = append(s.NodesTransitioning, truncationString)
	}
}

func (s *WorkloadPolicyStatus) addNodeIssue(nodeName string, status PolicyStatus) {
	// we always increment the failure count
	s.FailedNodes++

	if s.NodesWithIssues == nil {
		s.NodesWithIssues = make(map[string]PolicyStatus, maxNodesWithIssues)
	}

	// we store up to maxNodesWithIssues-1, the last element will be a marker of max reached
	if len(s.NodesWithIssues) < maxNodesWithIssues-1 {
		s.NodesWithIssues[nodeName] = status
	} else if len(s.NodesWithIssues) == maxNodesWithIssues-1 {
		s.NodesWithIssues[truncationString] = PolicyStatus{
			Code:    PolicyFailed,
			Message: truncationMessage,
		}
	}
}

func (s *WorkloadPolicyStatus) ProcessPolicyNodeStatus(nodes []PolicyNodeStatus) error {
	s.NodesWithIssues = nil
	s.NodesTransitioning = nil
	s.TotalNodes = len(nodes)
	s.SuccessfulNodes = 0
	s.FailedNodes = 0
	s.TransitioningNodes = 0

	for _, status := range nodes {
		switch status.Code {
		case PolicyReady:
			s.SuccessfulNodes++
		case PolicyTransitioning:
			s.addTransitioningNode(status.NodeName)
		case PolicyFailed, PolicyMissing:
			s.addNodeIssue(status.NodeName, PolicyStatus{Code: status.Code, Message: status.Message})
		case PolicyUnknown:
			fallthrough
		default:
			return fmt.Errorf("unknown node status state %q for node %q", status.Code, status.NodeName)
		}
	}

	// We order the slice to avoid resource status updates in case of different order
	if len(s.NodesTransitioning) > 0 {
		slices.SortFunc(s.NodesTransitioning, strings.Compare)
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
