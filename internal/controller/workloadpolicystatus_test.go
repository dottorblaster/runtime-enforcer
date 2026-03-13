package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	// use the formatted output to avoid the new line
	w.t.Logf("%s", string(p))
	return len(p), nil
}

func createTestWPStatusSync(t *testing.T) *WorkloadPolicyStatusSync {
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	v1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
	config := &WorkloadPolicyStatusSyncConfig{
		AgentPoolConf: grpcexporter.AgentClientPoolConfig{
			AgentFactoryConfig: grpcexporter.AgentFactoryConfig{
				Port:        50051,
				MTLSEnabled: false,
			},
			LabelSelectorString: "app=agent",
			// We explicitly provide a namespace so that this is not computed at runtime.
			Namespace: "test-namespace",
			Logger: slog.New(slog.NewJSONHandler(&testLogWriter{t: t}, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})).With("component", "agent-pool"),
		},
		UpdateInterval: 1 * time.Second,
	}

	r, err := NewWorkloadPolicyStatusSync(cl, config)
	require.NoError(t, err)
	return r
}

type testAgentClient struct {
	policies   map[string]*pb.PolicyStatus
	violations []*pb.ViolationRecord
	scrapeErr  error
}

func (c *testAgentClient) ListPoliciesStatus(_ context.Context) (map[string]*pb.PolicyStatus, error) {
	return c.policies, nil
}

func (c *testAgentClient) ListPodCache(_ context.Context) ([]*pb.PodView, error) {
	return nil, nil
}

func (c *testAgentClient) ScrapeViolations(_ context.Context) ([]*pb.ViolationRecord, error) {
	return c.violations, c.scrapeErr
}

func (c *testAgentClient) Close() error {
	return nil
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
					node1: {Code: v1alpha1.NodeIssueMissingPolicy},
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

func makeRecord(i int) v1alpha1.ViolationRecord {
	return v1alpha1.ViolationRecord{
		Timestamp:      metav1.NewTime(time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)),
		PodName:        fmt.Sprintf("pod-%d", i),
		ContainerName:  "c",
		ExecutablePath: "/usr/bin/test",
		NodeName:       "node-1",
		Action:         "monitor",
	}
}

func TestMergeViolations(t *testing.T) {
	tests := []struct {
		name     string
		existing []v1alpha1.ViolationRecord
		scraped  []v1alpha1.ViolationRecord
		expected []v1alpha1.ViolationRecord
	}{
		{
			name:     "both nil/empty returns nil",
			existing: nil,
			scraped:  nil,
			expected: nil,
		},
		{
			name:     "scraped only",
			existing: nil,
			scraped:  []v1alpha1.ViolationRecord{makeRecord(2), makeRecord(1)},
			expected: []v1alpha1.ViolationRecord{makeRecord(2), makeRecord(1)},
		},
		{
			name:     "existing only",
			existing: []v1alpha1.ViolationRecord{makeRecord(1)},
			scraped:  nil,
			expected: []v1alpha1.ViolationRecord{makeRecord(1)},
		},
		{
			name:     "scraped prepended before existing",
			existing: []v1alpha1.ViolationRecord{makeRecord(1)},
			scraped:  []v1alpha1.ViolationRecord{makeRecord(3), makeRecord(2)},
			expected: []v1alpha1.ViolationRecord{makeRecord(3), makeRecord(2), makeRecord(1)},
		},
		{
			name: "trims to MaxViolationRecords",
			existing: func() []v1alpha1.ViolationRecord {
				recs := make([]v1alpha1.ViolationRecord, v1alpha1.MaxViolationRecords)
				for i := range recs {
					recs[i] = makeRecord(i)
				}
				return recs
			}(),
			scraped: []v1alpha1.ViolationRecord{makeRecord(999)},
			expected: func() []v1alpha1.ViolationRecord {
				recs := make([]v1alpha1.ViolationRecord, v1alpha1.MaxViolationRecords)
				recs[0] = makeRecord(999)
				for i := 1; i < v1alpha1.MaxViolationRecords; i++ {
					recs[i] = makeRecord(i - 1)
				}
				return recs
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeViolations(tt.existing, tt.scraped)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestGetViolationsByPolicy(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	pbRec := func(policy, pod, node string) *pb.ViolationRecord {
		return &pb.ViolationRecord{
			Timestamp:      timestamppb.New(ts),
			PolicyName:     policy,
			PodName:        pod,
			ContainerName:  "c",
			ExecutablePath: "/usr/bin/test",
			NodeName:       node,
			Action:         "monitor",
		}
	}

	apiRec := func(pod, node string) v1alpha1.ViolationRecord {
		return v1alpha1.ViolationRecord{
			Timestamp:      metav1.NewTime(ts),
			PodName:        pod,
			ContainerName:  "c",
			ExecutablePath: "/usr/bin/test",
			NodeName:       node,
			Action:         "monitor",
		}
	}

	t.Run("collects violations from healthy nodes", func(t *testing.T) {
		r := createTestWPStatusSync(t)

		client1 := &testAgentClient{
			violations: []*pb.ViolationRecord{
				pbRec("default/policy-a", "pod-1", "node1"),
			},
		}
		client2 := &testAgentClient{
			violations: []*pb.ViolationRecord{
				pbRec("default/policy-a", "pod-2", "node2"),
				pbRec("default/policy-b", "pod-3", "node2"),
			},
		}
		clients := map[string]grpcexporter.AgentClientAPI{
			"node1": client1,
			"node2": client2,
		}

		got := r.getViolationsByPolicy(context.Background(), clients)

		nnA := types.NamespacedName{Namespace: "default", Name: "policy-a"}
		nnB := types.NamespacedName{Namespace: "default", Name: "policy-b"}

		require.Len(t, got[nnA], 2)
		require.Contains(t, got[nnA], apiRec("pod-1", "node1"))
		require.Contains(t, got[nnA], apiRec("pod-2", "node2"))
		require.Equal(t, []v1alpha1.ViolationRecord{apiRec("pod-3", "node2")}, got[nnB])
	})

	t.Run("skips nodes without connection", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		// No connections set up.

		clients := map[string]grpcexporter.AgentClientAPI{
			"node1": nil, // Simulate no connection to node1
		}

		got := r.getViolationsByPolicy(context.Background(), clients)
		require.Empty(t, got)
	})

	t.Run("skips node on scrape error", func(t *testing.T) {
		r := createTestWPStatusSync(t)

		clients := map[string]grpcexporter.AgentClientAPI{
			"node1": &testAgentClient{scrapeErr: errors.New("connection refused")},
		}

		got := r.getViolationsByPolicy(context.Background(), clients)
		require.Empty(t, got)
	})

	t.Run("empty nodes returns empty map", func(t *testing.T) {
		r := createTestWPStatusSync(t)
		got := r.getViolationsByPolicy(context.Background(), nil)
		require.Empty(t, got)
	})
}

func TestParsePolicyNamespacedName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    types.NamespacedName
		wantErr bool
	}{
		{
			name:  "valid namespace/name",
			input: "default/my-policy",
			want:  types.NamespacedName{Namespace: "default", Name: "my-policy"},
		},
		{
			name:  "name with extra slashes",
			input: "ns/name/with/slashes",
			want:  types.NamespacedName{Namespace: "ns", Name: "name/with/slashes"},
		},
		{
			name:    "no namespace",
			input:   "just-a-name",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePolicyNamespacedName(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
