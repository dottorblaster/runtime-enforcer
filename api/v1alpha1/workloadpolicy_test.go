package v1alpha1_test

import (
	"strconv"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadPolicyNamespacedName(t *testing.T) {
	wp := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-namespace",
			Name:      "test-name",
		},
	}
	expected := "test-namespace/test-name"
	require.Equal(t, expected, wp.NamespacedName())
}

func TestAddNodeIssue(t *testing.T) {
	wp := &v1alpha1.WorkloadPolicy{
		Status: v1alpha1.WorkloadPolicyStatus{},
	}
	issue := v1alpha1.NodeIssue{
		Code:    v1alpha1.NodeIssueMissingPolicy,
		Message: "Test message",
	}

	for i := range v1alpha1.MaxNodesWithIssues + 10 {
		wp.Status.AddNodeIssue(strconv.Itoa(i), issue)
	}
	// now we should have just MaxNodesWithIssues
	require.Len(t, wp.Status.NodesWithIssues, v1alpha1.MaxNodesWithIssues)
	// but the failed counter should reflect the actual number of failed nodes
	require.Equal(t, v1alpha1.MaxNodesWithIssues+10, wp.Status.FailedNodes)
	require.Contains(t, wp.Status.NodesWithIssues, v1alpha1.TruncationNodeString)
}

func TestAddTransitioningNode(t *testing.T) {
	wp := &v1alpha1.WorkloadPolicy{
		Status: v1alpha1.WorkloadPolicyStatus{},
	}

	for i := range v1alpha1.MaxTransitioningNodes + 12 {
		wp.Status.AddTransitioningNode(strconv.Itoa(i))
	}

	// now we should have just MaxTransitioningNodes
	require.Len(t, wp.Status.NodesTransitioning, v1alpha1.MaxTransitioningNodes)
	// but the transitioning counter should reflect the actual number of transitioning nodes
	require.Equal(t, v1alpha1.MaxTransitioningNodes+12, wp.Status.TransitioningNodes)
	require.Contains(t, wp.Status.NodesTransitioning, v1alpha1.TruncationNodeString)
}
