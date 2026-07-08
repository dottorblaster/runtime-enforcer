package v1alpha1

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddNodeIssue(t *testing.T) {
	wpStatus := WorkloadPolicyStatus{}
	policyStatus := PolicyStatus{
		Code:    PolicyMissing,
		Message: "Test message",
	}

	numFailures := maxNodesWithIssues + 10
	for i := range numFailures {
		wpStatus.addNodeIssue(strconv.Itoa(i), policyStatus)
	}
	// now we should have just maxNodesWithIssues
	require.Len(t, wpStatus.NodesWithIssues, maxNodesWithIssues)
	// but the failed counter should reflect the actual number of failed nodes
	require.Equal(t, numFailures, wpStatus.FailedNodes)
	// The truncation string should be present
	require.Contains(t, wpStatus.NodesWithIssues, truncationString)
}

func TestAddTransitioningNode(t *testing.T) {
	wpStatus := WorkloadPolicyStatus{}

	numTransitioning := maxTransitioningNodes + 12
	for i := range numTransitioning {
		wpStatus.addTransitioningNode(strconv.Itoa(i))
	}

	// now we should have just maxTransitioningNodes
	require.Len(t, wpStatus.NodesTransitioning, maxTransitioningNodes)
	// but the transitioning counter should reflect the actual number of transitioning nodes
	require.Equal(t, numTransitioning, wpStatus.TransitioningNodes)
	// The truncation string should be present
	require.Contains(t, wpStatus.NodesTransitioning, truncationString)
}

func TestProcessPolicyNodeStatus(t *testing.T) {
	node1, node2, node3 := "node1", "node2", "node3"

	tests := []struct {
		name     string
		nodes    []PolicyNodeStatus
		expected WorkloadPolicyStatus
	}{
		{
			name: "policy_is_missing",
			nodes: []PolicyNodeStatus{
				{NodeName: node1, PolicyStatus: PolicyStatus{Code: PolicyMissing, Message: "No policies found"}},
				{NodeName: node2, PolicyStatus: PolicyStatus{Code: PolicyReady}},
				{NodeName: node3, PolicyStatus: PolicyStatus{Code: PolicyTransitioning}},
			},
			expected: WorkloadPolicyStatus{
				NodesWithIssues: map[string]PolicyStatus{
					node1: {Code: PolicyMissing, Message: "No policies found"},
				},
				TotalNodes:         3,
				SuccessfulNodes:    1,
				FailedNodes:        1,
				TransitioningNodes: 1,
				NodesTransitioning: []string{node3},
				Phase:              Failed,
			},
		},
		{
			name: "policy_is_transitioning",
			nodes: []PolicyNodeStatus{
				{NodeName: node1, PolicyStatus: PolicyStatus{Code: PolicyReady}},
				{NodeName: node2, PolicyStatus: PolicyStatus{Code: PolicyTransitioning}},
				{NodeName: node3, PolicyStatus: PolicyStatus{Code: PolicyTransitioning}},
			},
			expected: WorkloadPolicyStatus{
				NodesWithIssues:    nil,
				TotalNodes:         3,
				SuccessfulNodes:    1,
				FailedNodes:        0,
				TransitioningNodes: 2,
				NodesTransitioning: []string{node2, node3},
				Phase:              Transitioning,
			},
		},
		{
			name: "policy_is_active",
			nodes: []PolicyNodeStatus{
				{NodeName: node1, PolicyStatus: PolicyStatus{Code: PolicyReady}},
				{NodeName: node2, PolicyStatus: PolicyStatus{Code: PolicyReady}},
				{NodeName: node3, PolicyStatus: PolicyStatus{Code: PolicyReady}},
			},
			expected: WorkloadPolicyStatus{
				NodesWithIssues:    nil,
				TotalNodes:         3,
				SuccessfulNodes:    3,
				FailedNodes:        0,
				TransitioningNodes: 0,
				NodesTransitioning: nil,
				Phase:              Ready,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wpStatus := WorkloadPolicyStatus{}
			wpStatus.ProcessPolicyNodeStatus(tt.nodes)
			require.Equal(t, tt.expected, wpStatus)
		})
	}
}
