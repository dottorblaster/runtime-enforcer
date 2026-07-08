package v1alpha1

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddNodeIssue(t *testing.T) {
	wp := &WorkloadPolicy{
		Status: WorkloadPolicyStatus{},
	}
	issue := NodeIssue{
		Code:    NodeIssueMissingPolicy,
		Message: "Test message",
	}

	for i := range MaxNodesWithIssues + 10 {
		wp.Status.AddNodeIssue(strconv.Itoa(i), issue)
	}
	// now we should have just MaxNodesWithIssues
	require.Len(t, wp.Status.NodesWithIssues, MaxNodesWithIssues)
	// but the failed counter should reflect the actual number of failed nodes
	require.Equal(t, MaxNodesWithIssues+10, wp.Status.FailedNodes)
	require.Contains(t, wp.Status.NodesWithIssues, TruncationNodeString)
}

func TestAddTransitioningNode(t *testing.T) {
	wp := &WorkloadPolicy{
		Status: WorkloadPolicyStatus{},
	}

	for i := range MaxTransitioningNodes + 12 {
		wp.Status.AddTransitioningNode(strconv.Itoa(i))
	}

	// now we should have just MaxTransitioningNodes
	require.Len(t, wp.Status.NodesTransitioning, MaxTransitioningNodes)
	// but the transitioning counter should reflect the actual number of transitioning nodes
	require.Equal(t, MaxTransitioningNodes+12, wp.Status.TransitioningNodes)
	require.Contains(t, wp.Status.NodesTransitioning, TruncationNodeString)
}
