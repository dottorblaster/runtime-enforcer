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

// withID returns a copy of r with the given id.
func withID(r v1alpha1.ViolationRecord, id int64) v1alpha1.ViolationRecord {
	r.ID = id
	return r
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

	r := createTestWPStatusSync(t)

	_, err := r.processPolicyStatus(wp, nil, []v1alpha1.ViolationRecord{newViolation}, metav1.NewTime(time.Now()))
	status := wp.Status
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
