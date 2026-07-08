package v1alpha1

import "slices"

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
