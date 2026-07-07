package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/runtime-enforcer/internal/testutil"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/workloadkind"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

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
			Logger:    testutil.NewTestLogger(t),
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
				Phase:              v1alpha1.Ready,
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

// withID returns a copy of r with the given id.
func withID(r v1alpha1.ViolationRecord, id int64) v1alpha1.ViolationRecord {
	r.ID = id
	return r
}

// withPod returns a copy of r with the given pod name.
func withPod(r v1alpha1.ViolationRecord, pod string) v1alpha1.ViolationRecord {
	r.PodName = pod
	return r
}

func TestResolveScrapedViolations(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// base record used as a template for building test fixtures.
	base := v1alpha1.ViolationRecord{
		Timestamp:      metav1.NewTime(ts),
		PodName:        "pod-a",
		ContainerName:  "c",
		ExecutablePath: "/x",
		NodeName:       "node-1",
		Action:         "monitor",
	}

	type resolveTestCase struct {
		name      string
		existing  []v1alpha1.ViolationRecord
		scraped   []v1alpha1.ViolationRecord
		count     int64
		wantCount int64
		// wantMerged is the expected merged list. nil means skip merged
		// equality (for cases that need custom assertions via check).
		wantMerged []v1alpha1.ViolationRecord
		// check is an optional function for custom assertions. When set,
		// it overrides wantMerged.
		check func(t *testing.T, merged []v1alpha1.ViolationRecord)
	}

	tests := []resolveTestCase{
		{
			name:      "both nil/empty leaves the counter untouched",
			count:     0,
			wantCount: 0,
			check: func(t *testing.T, merged []v1alpha1.ViolationRecord) {
				require.Nil(t, merged)
			},
		},
		{
			name: "scraped only gets new ids starting from count",
			scraped: []v1alpha1.ViolationRecord{
				withPod(base, "pod-a"),
				withPod(base, "pod-b"),
			},
			count:     5,
			wantCount: 7,
			wantMerged: []v1alpha1.ViolationRecord{
				withID(withPod(base, "pod-a"), 5),
				withID(withPod(base, "pod-b"), 6),
			},
		},
		{
			name: "matched re-scraped record keeps id and workload fields",
			existing: []v1alpha1.ViolationRecord{{
				ID:             5,
				Timestamp:      metav1.NewTime(ts.Add(-time.Hour)),
				PodName:        "pod-a",
				ContainerName:  "c",
				ExecutablePath: "/x",
				NodeName:       "node-1",
				Action:         "monitor",
				WorkloadName:   "my-deploy",
				WorkloadKind:   workloadkind.Deployment.String(),
			}},
			scraped: []v1alpha1.ViolationRecord{{
				Timestamp:      metav1.NewTime(ts),
				PodName:        "pod-a",
				ContainerName:  "c",
				ExecutablePath: "/x",
				NodeName:       "node-2",
				Action:         "monitor",
			}},
			count:     5,
			wantCount: 6,
			check: func(t *testing.T, merged []v1alpha1.ViolationRecord) {
				require.Len(t, merged, 1)
				got := merged[0]
				require.Equal(t, int64(5), got.ID, "id must be preserved across re-scrapes")
				require.Equal(t, "my-deploy", got.WorkloadName, "workload name must be preserved")
				require.Equal(t, string(workloadkind.Deployment), got.WorkloadKind, "workload kind must be preserved")
				require.Equal(t, metav1.NewTime(ts), got.Timestamp, "timestamp must move to the latest scrape")
				// NodeName is NOT updated on dedup — the dedup key includes
				// podName so the node is always the same for a given pod.
				require.Equal(t, "node-1", got.NodeName, "node must NOT be updated on re-scrape")
			},
		},
		{
			name:     "dedup key excludes node: different node is the same record",
			existing: []v1alpha1.ViolationRecord{withID(base, 10)},
			scraped: []v1alpha1.ViolationRecord{
				withID(base, 0),
			},
			count:     10,
			wantCount: 11,
			check: func(t *testing.T, merged []v1alpha1.ViolationRecord) {
				require.Len(t, merged, 1)
				// Existing record was updated in place, preserving its id.
				require.Equal(t, int64(10), merged[0].ID)
			},
		},
		{
			name:     "new records are appended then sorted by timestamp",
			existing: []v1alpha1.ViolationRecord{withID(makeRecord(1), 1)},
			scraped: []v1alpha1.ViolationRecord{
				makeRecord(3),
				makeRecord(2),
			},
			count:     5,
			wantCount: 7,
			wantMerged: []v1alpha1.ViolationRecord{
				withID(makeRecord(3), 5),
				withID(makeRecord(2), 6),
				withID(makeRecord(1), 1),
			},
		},
		{
			name: "list is trimmed to MaxViolationRecords",
			existing: func() []v1alpha1.ViolationRecord {
				r := make([]v1alpha1.ViolationRecord, v1alpha1.MaxViolationRecords)
				for i := range r {
					r[i] = withID(makeRecord(i), int64(i+1))
				}
				return r
			}(),
			scraped:   []v1alpha1.ViolationRecord{withPod(makeRecord(999), "pod-999")},
			count:     101,
			wantCount: 102,
			check: func(t *testing.T, merged []v1alpha1.ViolationRecord) {
				require.Len(t, merged, v1alpha1.MaxViolationRecords)
				require.Equal(t, "pod-999", merged[0].PodName, "new record sits at the top")
				// After sorting by timestamp, the oldest existing record
				// (id=1, pod-0, ts=second 0) ends up at the tail and is
				// dropped. The new tail is id=2, pod-1.
				require.Equal(t, int64(2), merged[v1alpha1.MaxViolationRecords-1].ID,
					"oldest existing is dropped")
			},
		},
		{
			name: "workload fields from scraped records are preserved for new entries",
			scraped: []v1alpha1.ViolationRecord{{
				Timestamp:      metav1.NewTime(ts),
				PodName:        "pod-a",
				ContainerName:  "c",
				ExecutablePath: "/x",
				NodeName:       "n1",
				Action:         "monitor",
				WorkloadName:   "my-app",
				WorkloadKind:   workloadkind.Deployment.String(),
			}, {
				Timestamp:      metav1.NewTime(ts),
				PodName:        "pod-orphan",
				ContainerName:  "c",
				ExecutablePath: "/x",
				NodeName:       "n1",
				Action:         "monitor",
			}},
			count:     0,
			wantCount: 2,
			check: func(t *testing.T, merged []v1alpha1.ViolationRecord) {
				require.Len(t, merged, 2)
				require.Equal(t, "my-app", merged[0].WorkloadName)
				require.Equal(t, string(workloadkind.Deployment), merged[0].WorkloadKind)
				require.Empty(t, merged[1].WorkloadName)
				require.Empty(t, merged[1].WorkloadKind)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merged, gotCount := resolveScrapedViolations(tt.existing, tt.scraped, tt.count)
			require.Equal(t, tt.wantCount, gotCount, "violation count")
			if tt.check != nil {
				tt.check(t, merged)
			} else if tt.wantMerged != nil {
				require.Equal(t, tt.wantMerged, merged)
			}
		})
	}

	// Separate subtest for the dedup-key composition: each field (pod,
	// container, executable, action) independently prevents dedup, while
	// node is intentionally excluded from the key. This is inherently a
	// multi-case assertion that doesn't fit into the simple table above.
	t.Run("dedup key is composed of pod, container, executable, action", func(t *testing.T) {
		existing := []v1alpha1.ViolationRecord{withID(base, 10)}

		cases := []struct {
			name   string
			mutate func(*v1alpha1.ViolationRecord)
		}{
			{"different pod", func(r *v1alpha1.ViolationRecord) { r.PodName = "pod-b" }},
			{"different container", func(r *v1alpha1.ViolationRecord) { r.ContainerName = "c2" }},
			{"different executable", func(r *v1alpha1.ViolationRecord) { r.ExecutablePath = "/y" }},
			{"different action", func(r *v1alpha1.ViolationRecord) { r.Action = "protect" }},
			// Node is intentionally NOT in the dedup key.
			{"different node dedups (not in key)", nil},
		}

		scraped := make([]v1alpha1.ViolationRecord, 0, len(cases))
		expectedNew := 0
		for _, tc := range cases {
			r := base
			if tc.mutate != nil {
				tc.mutate(&r)
				expectedNew++
			}
			scraped = append(scraped, r)
		}

		merged, count := resolveScrapedViolations(existing, scraped, 14)
		require.Equal(t, int64(19), count, "count is bumped for every scraped record")
		require.Len(t, merged, 1+expectedNew)
		require.Equal(t, int64(10), merged[0].ID, "existing record stays at head")
	})
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

		nnA := "default/policy-a"
		nnB := "default/policy-b"

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

func TestClearAllowedViolations(t *testing.T) {
	createViolationRecord := func(container, exe string) v1alpha1.ViolationRecord {
		return v1alpha1.ViolationRecord{
			ContainerName:  container,
			ExecutablePath: exe,
		}
	}

	tests := []struct {
		name       string
		violations []v1alpha1.ViolationRecord
		rules      map[string]*v1alpha1.WorkloadPolicyRules
		expected   []v1alpha1.ViolationRecord
	}{
		{
			name: "drops violations for allowed executable/container pairs",
			violations: []v1alpha1.ViolationRecord{
				createViolationRecord("app", "/usr/bin/app"),
				createViolationRecord("app", "/usr/bin/other"),
				createViolationRecord("sidecar", "/usr/bin/app"),
			},
			rules: map[string]*v1alpha1.WorkloadPolicyRules{
				"app": {
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/usr/bin/app", "/bin/sh"},
					},
				},
			},
			expected: []v1alpha1.ViolationRecord{
				createViolationRecord("app", "/usr/bin/other"),
				createViolationRecord("sidecar", "/usr/bin/app"),
			},
		},
		{
			name:       "nil rules leave violations untouched",
			violations: []v1alpha1.ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
			rules:      nil,
			expected:   []v1alpha1.ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
		},
		{
			name:       "empty rules leave violations untouched",
			violations: []v1alpha1.ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
			rules:      map[string]*v1alpha1.WorkloadPolicyRules{},
			expected:   []v1alpha1.ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
		},
		{
			name:       "container with nil rules does not panic",
			violations: []v1alpha1.ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
			rules:      map[string]*v1alpha1.WorkloadPolicyRules{"app": nil},
			expected:   []v1alpha1.ViolationRecord{createViolationRecord("app", "/usr/bin/app")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wp := &v1alpha1.WorkloadPolicy{
				Spec:   v1alpha1.WorkloadPolicySpec{RulesByContainer: tt.rules},
				Status: v1alpha1.WorkloadPolicyStatus{Violations: tt.violations},
			}
			got := wp.ClearAllowed()
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestBuildPolicyStatusClearanceFreesCapForNewViolations(t *testing.T) {
	ns := "ns"
	mode := policymode.MonitorString

	// Fill existing violations to the cap. The first record (id=1) is for
	// an executable that will be allowed, so it gets cleared and makes room.
	existing := make([]v1alpha1.ViolationRecord, v1alpha1.MaxViolationRecords)
	for i := range existing {
		existing[i] = withID(v1alpha1.ViolationRecord{
			Timestamp:      metav1.NewTime(time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)),
			PodName:        fmt.Sprintf("pod-%d", i),
			ContainerName:  "app",
			ExecutablePath: fmt.Sprintf("/usr/bin/exe-%d", i),
			NodeName:       "node-1",
			Action:         "monitor",
		}, int64(i+1))
	}

	wp := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns},
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: mode,
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				"app": {
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{"/usr/bin/exe-0"},
					},
				},
			},
		},
		Status: v1alpha1.WorkloadPolicyStatus{
			ViolationCount: int64(v1alpha1.MaxViolationRecords),
			Violations:     existing,
		},
	}

	// Add a brand-new violation that would have been dropped if the cap had
	// not been freed by clearing exe-0.
	removedViolation := existing[0]
	newViolation := v1alpha1.ViolationRecord{
		Timestamp:      metav1.NewTime(time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)),
		PodName:        "pod-new",
		ContainerName:  "app",
		ExecutablePath: "/usr/bin/new-exe",
		NodeName:       "node-2",
		Action:         "monitor",
	}

	status, err := buildPolicyStatus(wp, nil, []v1alpha1.ViolationRecord{newViolation})
	require.NoError(t, err)
	require.Len(t, status.Violations, v1alpha1.MaxViolationRecords,
		"list should remain at the cap after clearance + merge")
	require.Equal(t, int64(v1alpha1.MaxViolationRecords+1), status.ViolationCount,
		"ViolationCount must account for the new observed violation")
	require.Equal(t, v1alpha1.MaxViolationRecords, status.ActiveViolationCount,
		"ActiveViolationCount must equal len(Violations)")

	// exe-0 should be gone, /usr/bin/new-exe should be present.
	newViolation.ID = int64(v1alpha1.MaxViolationRecords)
	require.Contains(t, status.Violations, newViolation)
	require.NotContains(t, status.Violations, removedViolation)
}
