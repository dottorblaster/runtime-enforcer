//nolint:testpackage //we want to test unexported functions
package controller

import (
	"context"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func createTestWPStatusSync(t *testing.T) *WorkloadPolicyStatusSync {
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	v1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
	config := &WorkloadPolicyStatusSyncConfig{
		AgentGRPCConf: AgentGRPCConfig{
			Port:        50051,
			MTLSEnabled: false,
		},
		UpdateInterval:     1 * time.Second,
		AgentNamespace:     "test-namespace",
		AgentLabelSelector: "app=agent",
	}

	r, err := NewWorkloadPolicyStatusSync(cl, config)
	require.NoError(t, err)
	return r
}

type testAgentClient struct {
	policies map[string]*pb.PolicyStatus
}

func newTestAgentClient(policies map[string]*pb.PolicyStatus) *testAgentClient {
	return &testAgentClient{
		policies: policies,
	}
}

func (c *testAgentClient) listPoliciesStatus(_ context.Context) (map[string]*pb.PolicyStatus, error) {
	return c.policies, nil
}

func (c *testAgentClient) close() error {
	return nil
}

func TestGCStaleConnections(t *testing.T) {
	r := createTestWPStatusSync(t)

	node1, node2, node3 := "node1", "node2", "node3"
	mockAgentClient := newTestAgentClient(nil)

	// populate the connections for the controller
	r.conns = map[string]agentClientAPI{
		node1: mockAgentClient,
		node2: mockAgentClient,
		node3: mockAgentClient,
	}

	// node3 is no more present in the cluster we should remove it.
	podList := &corev1.PodList{
		Items: []corev1.Pod{
			{
				Spec: corev1.PodSpec{NodeName: node1},
			},
			{
				Spec: corev1.PodSpec{NodeName: node2},
			},
		},
	}
	r.gcStaleConnections(podList)
	require.Equal(t, map[string]agentClientAPI{
		node1: mockAgentClient,
		node2: mockAgentClient,
	}, r.conns)
}

func TestComputeWpStatus(t *testing.T) {
	policyName := "example"
	expectedMode := pb.PolicyMode_POLICY_MODE_PROTECT
	wrongMode := pb.PolicyMode_POLICY_MODE_MONITOR
	node1, node2, node3 := "node1", "node2", "node3"

	tests := []struct {
		name     string
		nodes    nodesInfoMap
		expected v1alpha1.WorkloadPolicyStatus
	}{
		{
			// - node1 is in an error condition because it has no policies.
			// - node2 has the policy ready in the right mode.
			// - node3 has the policy ready in the wrong mode.
			name: "node with missing policies",
			nodes: nodesInfoMap{
				node1: nodeInfo{issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueMissingPolicy}},
				node2: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  expectedMode,
						},
					},
				},
				node3: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  wrongMode,
						},
					},
				},
			},
			expected: v1alpha1.WorkloadPolicyStatus{
				NodesWithIssues: map[string]v1alpha1.NodeIssue{
					node1: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueMissingPolicy},
				},
				TotalNodes:         3,
				SuccessfulNodes:    1,
				FailedNodes:        1,
				TransitioningNodes: 1,
				NodesTransitioning: []string{node3},
				Phase:              v1alpha1.Failed,
			},
		},
		{
			// - node1 has the policy ready in the right mode.
			// - node2 has the policy ready in the wrong mode.
			// - node3 has the policy ready in the wrong mode.
			name: "policy is transitioning",
			nodes: nodesInfoMap{
				node1: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  expectedMode,
						},
					},
				},
				node2: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  wrongMode,
						},
					},
				},
				node3: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  wrongMode,
						},
					},
				},
			},
			expected: v1alpha1.WorkloadPolicyStatus{
				NodesWithIssues:    nil,
				TotalNodes:         3,
				SuccessfulNodes:    1,
				FailedNodes:        0,
				TransitioningNodes: 2,
				NodesTransitioning: []string{node2, node3},
				Phase:              v1alpha1.Transitioning,
			},
		},
		{
			// - node1 has the policy ready in the right mode.
			// - node2 has the policy ready in the right mode.
			// - node3 has the policy ready in the right mode.
			name: "policy is active",
			nodes: nodesInfoMap{
				node1: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  expectedMode,
						},
					},
				},
				node2: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  expectedMode,
						},
					},
				},
				node3: nodeInfo{
					issue: v1alpha1.NodeIssue{Code: v1alpha1.NodeIssueNone},
					policies: map[string]*pb.PolicyStatus{
						policyName: {
							State: pb.PolicyState_POLICY_STATE_READY,
							Mode:  expectedMode,
						},
					},
				},
			},
			expected: v1alpha1.WorkloadPolicyStatus{
				NodesWithIssues:    nil,
				TotalNodes:         3,
				SuccessfulNodes:    3,
				FailedNodes:        0,
				TransitioningNodes: 0,
				NodesTransitioning: nil,
				Phase:              v1alpha1.Active,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := computeWpStatus(tt.nodes, expectedMode, policyName)
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
		})
	}
}
