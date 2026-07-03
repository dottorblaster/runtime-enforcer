package controller

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/runtime-enforcer/internal/testutil"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	pb "github.com/rancher-sandbox/runtime-enforcer/proto/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

// workloadKindDeployment is the API kind string we use as a fixture for
// owner-reference-based workload resolution tests. Defining it as a constant
// keeps the linter happy about repeated string literals and reads as a
// named fixture.
const workloadKindDeployment = "Deployment"

func TestResolveScrapedViolations(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("both nil/empty leaves the counter untouched", func(t *testing.T) {
		merged, count := resolveScrapedViolations(nil, nil, 0)
		require.Nil(t, merged)
		require.Equal(t, int64(0), count)
	})

	t.Run("scraped only gets new ids starting from count+1", func(t *testing.T) {
		scraped := []v1alpha1.ViolationRecord{
			{
				Timestamp:      metav1.NewTime(ts),
				PodName:        "pod-a",
				ContainerName:  "c",
				ExecutablePath: "/x",
				NodeName:       "n1",
				Action:         "monitor",
			},
			{
				Timestamp:      metav1.NewTime(ts),
				PodName:        "pod-b",
				ContainerName:  "c",
				ExecutablePath: "/x",
				NodeName:       "n1",
				Action:         "monitor",
			},
		}
		merged, count := resolveScrapedViolations(nil, scraped, 5)
		require.Equal(t, int64(7), count, "count is bumped once per new record")
		require.Len(t, merged, 2)
		require.Equal(t, int64(6), merged[0].ID, "first new id is count+1")
		require.Equal(t, int64(7), merged[1].ID, "subsequent ids are monotonically increasing")
	})

	t.Run("matched re-scraped record keeps id and workload fields", func(t *testing.T) {
		// Existing record: id=5, owned by a Deployment, scraped an hour ago.
		// ViolationCount is 5 to match the highest allocated id.
		existing := []v1alpha1.ViolationRecord{{
			ID:             5,
			Timestamp:      metav1.NewTime(ts.Add(-time.Hour)),
			PodName:        "pod-a",
			ContainerName:  "c",
			ExecutablePath: "/x",
			NodeName:       "node-1",
			Action:         "monitor",
			WorkloadName:   "my-deploy",
			WorkloadKind:   workloadKindDeployment,
		}}
		// Re-scraped: same key (pod, container, executable, action), new
		// timestamp and a different node. Workload fields are left empty
		// in the scraped record — the existing ones should be preserved.
		newer := ts
		scraped := []v1alpha1.ViolationRecord{{
			Timestamp:      metav1.NewTime(newer),
			PodName:        "pod-a",
			ContainerName:  "c",
			ExecutablePath: "/x",
			NodeName:       "node-2",
			Action:         "monitor",
		}}

		merged, count := resolveScrapedViolations(existing, scraped, 5)
		require.Equal(t, int64(5), count, "count must not bump for a re-scraped record")
		require.Len(t, merged, 1)
		got := merged[0]
		require.Equal(t, int64(5), got.ID, "id must be preserved across re-scrapes")
		require.Equal(t, "my-deploy", got.WorkloadName, "workload name must be preserved")
		require.Equal(t, workloadKindDeployment, got.WorkloadKind, "workload kind must be preserved")
		require.Equal(t, metav1.NewTime(newer), got.Timestamp, "timestamp must move to the latest scrape")
		require.Equal(t, "node-2", got.NodeName, "node must follow the latest scrape")
	})

	t.Run("dedup uses policy, pod, container, executable, action only", func(t *testing.T) {
		// All four scraped records differ on exactly one key field from the
		// existing one; none of them should dedup.
		base := v1alpha1.ViolationRecord{
			Timestamp:      metav1.NewTime(ts),
			PodName:        "pod-a",
			ContainerName:  "c",
			ExecutablePath: "/x",
			NodeName:       "node-1",
			Action:         "monitor",
		}
		existing := []v1alpha1.ViolationRecord{withID(base, 10)}

		cases := []struct {
			name string
			mut  func(*v1alpha1.ViolationRecord)
		}{
			{"different pod", func(r *v1alpha1.ViolationRecord) { r.PodName = "pod-b" }},
			{"different container", func(r *v1alpha1.ViolationRecord) { r.ContainerName = "c2" }},
			{"different executable", func(r *v1alpha1.ViolationRecord) { r.ExecutablePath = "/y" }},
			{"different action", func(r *v1alpha1.ViolationRecord) { r.Action = "protect" }},
			// Node is intentionally NOT in the dedup key: a different node
			// on the same key is the same record.
			{"different node dedups", nil},
		}

		scraped := make([]v1alpha1.ViolationRecord, 0, len(cases))
		expectedNew := 0
		for _, tc := range cases {
			r := base
			if tc.mut != nil {
				tc.mut(&r)
			}
			scraped = append(scraped, r)
			if tc.mut != nil {
				expectedNew++
			}
		}

		merged, count := resolveScrapedViolations(existing, scraped, 10)
		require.Equal(t, int64(10+expectedNew), count, "count is bumped once per new record")
		require.Len(t, merged, 1+expectedNew)
		// New records are prepended, so the existing record (id=10) sits
		// at the tail of the merged list, after the newly allocated ones.
		require.Equal(t, int64(10), merged[len(merged)-1].ID)
	})

	t.Run("unmatched scraped records are prepended before existing", func(t *testing.T) {
		existing := []v1alpha1.ViolationRecord{withID(makeRecord(1), 5)}
		scraped := []v1alpha1.ViolationRecord{
			makeRecord(3), // new
			makeRecord(2), // new
		}
		merged, count := resolveScrapedViolations(existing, scraped, 5)
		require.Equal(t, int64(7), count)
		require.Len(t, merged, 3)
		require.Equal(t, "pod-3", merged[0].PodName)
		require.Equal(t, "pod-2", merged[1].PodName)
		require.Equal(t, "pod-1", merged[2].PodName)
	})

	t.Run("list is trimmed to MaxViolationRecords", func(t *testing.T) {
		existing := make([]v1alpha1.ViolationRecord, v1alpha1.MaxViolationRecords)
		for i := range existing {
			existing[i] = withID(makeRecord(i), int64(i+1))
		}
		scraped := []v1alpha1.ViolationRecord{withID(makeRecord(999), 0)}
		merged, count := resolveScrapedViolations(existing, scraped, 100)
		require.Equal(t, int64(101), count)
		require.Len(t, merged, v1alpha1.MaxViolationRecords)
		require.Equal(t, "pod-999", merged[0].PodName, "new record sits at the top")
		require.Equal(t, "pod-0", merged[1].PodName, "oldest existing is dropped")
	})

	t.Run("workload fields from scraped records are preserved for new entries", func(t *testing.T) {
		scraped := []v1alpha1.ViolationRecord{{
			Timestamp:      metav1.NewTime(ts),
			PodName:        "pod-a",
			ContainerName:  "c",
			ExecutablePath: "/x",
			NodeName:       "n1",
			Action:         "monitor",
			WorkloadName:   "my-app",
			WorkloadKind:   workloadKindDeployment,
		}, {
			Timestamp:      metav1.NewTime(ts),
			PodName:        "pod-orphan",
			ContainerName:  "c",
			ExecutablePath: "/x",
			NodeName:       "n1",
			Action:         "monitor",
			// No workload fields — e.g. the agent couldn't determine them.
		}}
		merged, _ := resolveScrapedViolations(nil, scraped, 0)
		require.Len(t, merged, 2)
		require.Equal(t, "my-app", merged[0].WorkloadName)
		require.Equal(t, workloadKindDeployment, merged[0].WorkloadKind)
		require.Empty(t, merged[1].WorkloadName)
		require.Empty(t, merged[1].WorkloadKind)
	})
}

// withID returns a copy of r with the given id.
func withID(r v1alpha1.ViolationRecord, id int64) v1alpha1.ViolationRecord {
	r.ID = id
	return r
}

func TestBuildPolicyStatusAtomicCounter(t *testing.T) {
	ns := "ns"

	t.Run("fresh policy: first record gets id 1 and count becomes 1", func(t *testing.T) {
		wp := &v1alpha1.WorkloadPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns},
			Spec:       v1alpha1.WorkloadPolicySpec{Mode: policymode.MonitorString},
		}
		scraped := []v1alpha1.ViolationRecord{makeRecord(1)}
		status, err := buildPolicyStatus(wp, nil, scraped)
		require.NoError(t, err)
		require.Equal(t, int64(1), status.ViolationCount)
		require.Len(t, status.Violations, 1)
		require.Equal(t, int64(1), status.Violations[0].ID)
	})

	t.Run("counter continues from the existing value", func(t *testing.T) {
		// Existing record has id=5; the count is 5 (equal to the highest
		// allocated id). One new record should land at id=6 and bump the
		// count to 6.
		existing := []v1alpha1.ViolationRecord{withID(makeRecord(1), 5)}
		wp := &v1alpha1.WorkloadPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns},
			Spec:       v1alpha1.WorkloadPolicySpec{Mode: policymode.MonitorString},
			Status: v1alpha1.WorkloadPolicyStatus{
				ViolationCount: 5,
				Violations:     existing,
			},
		}
		scraped := []v1alpha1.ViolationRecord{makeRecord(2)}
		status, err := buildPolicyStatus(wp, nil, scraped)
		require.NoError(t, err)
		require.Equal(t, int64(6), status.ViolationCount)
		require.Len(t, status.Violations, 2)
		require.Equal(t, int64(6), status.Violations[0].ID)
	})
}

func TestBuildPolicyStatusReScrapedKeepsId(t *testing.T) {
	ns := "ns"
	existing := []v1alpha1.ViolationRecord{{
		ID:             5,
		Timestamp:      metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)),
		PodName:        "pod-a",
		ContainerName:  "c",
		ExecutablePath: "/x",
		NodeName:       "node-1",
		Action:         "monitor",
		WorkloadName:   "my-deploy",
		WorkloadKind:   workloadKindDeployment,
	}}
	wp := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns},
		Spec:       v1alpha1.WorkloadPolicySpec{Mode: policymode.MonitorString},
		Status: v1alpha1.WorkloadPolicyStatus{
			ViolationCount: 5, // matches the highest allocated id (5)
			Violations:     existing,
		},
	}
	// Re-scraped record: same dedup key, new timestamp and node.
	rescraped := []v1alpha1.ViolationRecord{{
		Timestamp:      metav1.NewTime(time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)),
		PodName:        "pod-a",
		ContainerName:  "c",
		ExecutablePath: "/x",
		NodeName:       "node-2",
		Action:         "monitor",
	}}

	status, err := buildPolicyStatus(wp, nil, rescraped)
	require.NoError(t, err)
	require.Equal(t, int64(5), status.ViolationCount, "count must not bump for a dedup")
	require.Len(t, status.Violations, 1)
	got := status.Violations[0]
	require.Equal(t, int64(5), got.ID)
	require.Equal(t, "my-deploy", got.WorkloadName)
	require.Equal(t, workloadKindDeployment, got.WorkloadKind)
	require.Equal(t, "node-2", got.NodeName, "node follows the latest scrape")
	require.Equal(t, rescraped[0].Timestamp, got.Timestamp, "timestamp follows the latest scrape")
}

func TestWorkloadPolicyViolationCount(t *testing.T) {
	wp := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy",
			Namespace: "ns",
		},
		Spec: v1alpha1.WorkloadPolicySpec{Mode: policymode.MonitorString},
		Status: v1alpha1.WorkloadPolicyStatus{
			ViolationCount: 1, // one record already allocated (id=1)
			Violations:     []v1alpha1.ViolationRecord{withID(makeRecord(1), 1)},
		},
	}
	scraped := make([]v1alpha1.ViolationRecord, v1alpha1.MaxViolationRecords)
	for i := range scraped {
		scraped[i] = makeRecord(i + 2)
	}

	status, err := buildPolicyStatus(wp, nil, scraped)
	require.NoError(t, err)

	require.Equal(t, int64(101), status.ViolationCount)
	require.Len(t, status.Violations, v1alpha1.MaxViolationRecords)
}

// TestConcurrentReconcilesDoNotDoubleAllocate fakes a status-update conflict
// on the second concurrent reconcile and asserts that the policy never ends
// up with duplicate ids.
func TestConcurrentReconcilesDoNotDoubleAllocate(t *testing.T) {
	ctx := context.Background()
	ns := "ns"
	policyName := "policy"
	scrapeRec := v1alpha1.ViolationRecord{
		Timestamp:      metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		PodName:        "pod-a",
		ContainerName:  "c",
		ExecutablePath: "/x",
		NodeName:       "node-1",
		Action:         "monitor",
	}

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	baseClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&v1alpha1.WorkloadPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: ns},
			Spec:       v1alpha1.WorkloadPolicySpec{Mode: policymode.MonitorString},
			// A previously-active policy: 4 records have been allocated
			// (max id=4) and then trimmed out of the Violations slice.
			// The next allocation will stamp id=5 and bump the count to 5.
			Status: v1alpha1.WorkloadPolicyStatus{ViolationCount: 4},
		}).
		WithStatusSubresource(&v1alpha1.WorkloadPolicy{}).
		Build()

	var updates atomic.Int64
	cl := interceptor.NewClient(baseClient, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, subResource string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			n := updates.Add(1)
			if n == 2 {
				// Simulate an optimistic-concurrency conflict that the real
				// API server would raise if two reconciles raced for the
				// same record.
				return apierrors.NewConflict(
					schema.GroupResource{Group: "security.rancher.io", Resource: "workloadpolicies"},
					policyName,
					errors.New("resourceVersion changed"),
				)
			}
			return c.SubResource(subResource).Update(ctx, obj, opts...)
		},
	})

	r, err := NewWorkloadPolicyStatusSync(cl, &WorkloadPolicyStatusSyncConfig{
		AgentPoolConf: grpcexporter.AgentClientPoolConfig{
			AgentFactoryConfig:  grpcexporter.AgentFactoryConfig{Port: 50051, MTLSEnabled: false},
			LabelSelectorString: "app=agent",
			Namespace:           ns,
			Logger:              testutil.NewTestLogger(t),
		},
		UpdateInterval: time.Second,
	})
	require.NoError(t, err)

	// Two concurrent reconciles both try to allocate id=5 for the same
	// scraped violation. The fake client rejects the second Status().Update
	// with a conflict, so only one allocation should land.
	errCh := make(chan error, 2)
	for range 2 {
		go func() {
			wp := &v1alpha1.WorkloadPolicy{}
			if getErr := cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: policyName}, wp); getErr != nil {
				errCh <- getErr
				return
			}
			errCh <- r.processWorkloadPolicy(ctx, wp, nil, []v1alpha1.ViolationRecord{scrapeRec})
		}()
	}

	var firstErr, secondErr error
	for i := range 2 {
		select {
		case e := <-errCh:
			if i == 0 {
				firstErr = e
			} else {
				secondErr = e
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reconcile did not return in time")
		}
	}

	// Exactly one of the two reconciles must have observed a conflict.
	conflicts := 0
	for _, e := range []error{firstErr, secondErr} {
		if apierrors.IsConflict(e) {
			conflicts++
		}
	}
	require.Equal(
		t,
		1,
		conflicts,
		"exactly one reconcile should hit a conflict, got errors: %v, %v",
		firstErr,
		secondErr,
	)

	// And the persisted state must reflect a single id allocation.
	final := &v1alpha1.WorkloadPolicy{}
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: policyName}, final))
	require.Equal(t, int64(5), final.Status.ViolationCount, "count must be bumped exactly once")
	require.Len(t, final.Status.Violations, 1)
	require.Equal(t, int64(5), final.Status.Violations[0].ID, "only one id=5 should be allocated")
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
