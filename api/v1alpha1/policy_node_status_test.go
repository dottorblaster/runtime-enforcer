package v1alpha1

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAddNodeIssue(t *testing.T) {
	wpStatus := WorkloadPolicyStatus{}
	policyStatus := PolicyStatus{
		Code:    PolicyMissing,
		Message: "Test message",
	}

	numFailures := maxNodesWithIssues + 10
	for i := range numFailures {
		wpStatus.addNodeIssue(strconv.Itoa(i), policyStatus, PolicyStatus{}, time.Now())
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
		wpStatus.addTransitioningNode(PolicyNodeStatus{
			NodeName: strconv.Itoa(i),
			Code:     PolicyTransitioning,
		}, PolicyStatus{}, time.Now())
	}

	// now we should have just maxTransitioningNodes
	require.Len(t, wpStatus.NodesTransitioning, maxTransitioningNodes)
	// but the transitioning counter should reflect the actual number of transitioning nodes
	require.Equal(t, numTransitioning, wpStatus.TransitioningNodes)
	// The truncation string should be present
	require.Equal(t, truncationString, wpStatus.NodesTransitioning[maxTransitioningNodes-1].NodeName)
}

func TestProcessPolicyNodeStatus(t *testing.T) {
	node1, node2, node3 := "node1", "node2", "node3"
	now := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		nodes    []PolicyNodeStatus
		expected WorkloadPolicyStatus
	}{
		{
			name: "policy_is_missing",
			nodes: []PolicyNodeStatus{
				{NodeName: node1, Code: PolicyMissing, Message: "No policies found"},
				{NodeName: node2, Code: PolicyReady},
				{NodeName: node3, Code: PolicyTransitioning},
			},
			expected: WorkloadPolicyStatus{
				NodesWithIssues: map[string]PolicyStatus{
					node1: {Code: PolicyMissing, Message: "No policies found", Since: metav1.Time{Time: now}},
				},
				TotalNodes:         3,
				SuccessfulNodes:    1,
				FailedNodes:        1,
				TransitioningNodes: 1,
				NodesTransitioning: []PolicyNodeStatus{
					{
						NodeName: node3,
						Code:     PolicyTransitioning, Since: metav1.Time{Time: now},
					},
				},
				Phase: Failed,
			},
		},
		{
			name: "policy_is_transitioning",
			nodes: []PolicyNodeStatus{
				{NodeName: node1, Code: PolicyReady},
				{NodeName: node2, Code: PolicyTransitioning},
				{NodeName: node3, Code: PolicyTransitioning},
			},
			expected: WorkloadPolicyStatus{
				NodesWithIssues:    nil,
				TotalNodes:         3,
				SuccessfulNodes:    1,
				FailedNodes:        0,
				TransitioningNodes: 2,
				NodesTransitioning: []PolicyNodeStatus{
					{
						NodeName: node2,
						Code:     PolicyTransitioning, Since: metav1.Time{Time: now},
					},
					{
						NodeName: node3,
						Code:     PolicyTransitioning, Since: metav1.Time{Time: now},
					},
				},
				Phase: Transitioning,
			},
		},
		{
			name: "policy_is_active",
			nodes: []PolicyNodeStatus{
				{NodeName: node1, Code: PolicyReady},
				{NodeName: node2, Code: PolicyReady},
				{NodeName: node3, Code: PolicyReady},
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
			wpStatus.processPolicyNodeStatus(wpStatus, tt.nodes, now)
			require.Equal(t, tt.expected, wpStatus)
		})
	}
}

func TestProcessPolicyNodeStatusPreservesTransitionTime(t *testing.T) {
	node1, node2, node3 := "node1", "node2", "node3"
	baseTS := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	ts := func(sec int) time.Time {
		return baseTS.Add(time.Duration(sec) * time.Second)
	}

	// First observation: every node enters its current code, so all get stamped.
	status := WorkloadPolicyStatus{}
	nodes := []PolicyNodeStatus{
		{NodeName: node1, Code: PolicyFailed, Message: "boom"},
		{NodeName: node2, Code: PolicyTransitioning},
	}
	require.NoError(t, status.processPolicyNodeStatus(status, nodes, ts(1)))
	require.Equal(t, metav1.Time{Time: ts(1)}, status.NodesWithIssues[node1].Since)
	require.Equal(t, metav1.Time{Time: ts(1)}, status.NodesTransitioning[0].Since)

	// Unchanged codes: timestamps must be carried forward, not re-stamped.
	nodes = []PolicyNodeStatus{
		{NodeName: node1, Code: PolicyFailed, Message: "still boom"},
		{NodeName: node2, Code: PolicyTransitioning},
		{NodeName: node3, Code: PolicyMissing},
	}
	require.NoError(t, status.processPolicyNodeStatus(status, nodes, ts(2)))
	require.Equal(t, metav1.Time{Time: ts(1)}, status.NodesWithIssues[node1].Since)
	require.Equal(t, metav1.Time{Time: ts(1)}, status.NodesTransitioning[0].Since)
	require.Equal(t, metav1.Time{Time: ts(2)}, status.NodesWithIssues[node3].Since)

	// Code changes: timestamps must be reset. node1 goes Failed -> Ready (not
	// tracked) -> Failed, so it re-enters the Failed code at ts(4) and must be
	// re-stamped rather than keeping the ts(1) timestamp. node2 stays
	// Transitioning and keeps ts(1). node3 stays Missing and keeps ts(2).
	nodes = []PolicyNodeStatus{
		{NodeName: node1, Code: PolicyReady},
		{NodeName: node2, Code: PolicyTransitioning},
		{NodeName: node3, Code: PolicyMissing},
	}
	require.NoError(t, status.processPolicyNodeStatus(status, nodes, ts(3)))
	nodes = []PolicyNodeStatus{
		{NodeName: node1, Code: PolicyFailed, Message: "boom again"},
		{NodeName: node2, Code: PolicyTransitioning},
		{NodeName: node3, Code: PolicyMissing},
	}
	require.NoError(t, status.processPolicyNodeStatus(status, nodes, ts(4)))
	require.Equal(t, metav1.Time{Time: ts(4)}, status.NodesWithIssues[node1].Since)
	require.Equal(t, metav1.Time{Time: ts(1)}, status.NodesTransitioning[0].Since)
	require.Equal(t, metav1.Time{Time: ts(2)}, status.NodesWithIssues[node3].Since)
}
