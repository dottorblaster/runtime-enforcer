//nolint:testpackage // testing unexported policy handlers and wpState
package resolver

import (
	"log/slog"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mockPolicyUpdateBinariesFunc(_ PolicyID, _ []string, _ bpf.PolicyValuesOperation) error {
	return nil
}

func mockPolicyModeUpdateFunc(_ PolicyID, _ policymode.Mode, _ bpf.PolicyModeOperation) error {
	return nil
}

func mockCgTrackerUpdateFunc(_ uint64, _ string) error {
	return nil
}

func mockCgroupToPolicyMapUpdateFunc(_ PolicyID, _ []CgroupID, _ bpf.CgroupPolicyOperation) error {
	return nil
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	w.t.Log(string(p))
	return len(p), nil
}

func newTestResolver(t *testing.T) *Resolver {
	t.Helper()
	r, err := NewResolver(
		slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		mockCgTrackerUpdateFunc,
		mockCgroupToPolicyMapUpdateFunc,
		mockPolicyUpdateBinariesFunc,
		mockPolicyModeUpdateFunc,
	)
	require.NoError(t, err)
	return r
}

// TestHandleWP_Lifecycle exercises add → update → delete in one test so the policy is created once.
func TestHandleWP_Lifecycle(t *testing.T) {
	r := newTestResolver(t)
	wp := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "example", Namespace: "test-ns"},
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: "monitor",
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				"c1": {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/sleep"}}},
				"c2": {Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat"}}},
			},
		},
	}
	key := wp.NamespacedName()

	// Add
	require.NoError(t, r.handleWPAdd(wp))
	require.Contains(t, r.wpState, key)
	state := r.wpState[key]
	require.Len(t, state, 2)
	require.Contains(t, state, "c1")
	require.Contains(t, state, "c2")
	ids := make(map[PolicyID]struct{})
	for _, id := range state {
		ids[id] = struct{}{}
	}
	require.Equal(t, map[PolicyID]struct{}{PolicyID(1): {}, PolicyID(2): {}}, ids)
	initialState := r.wpState[key]

	// Update: remove c1, update c2 allowed list, add c3
	delete(wp.Spec.RulesByContainer, "c1")
	wp.Spec.RulesByContainer["c2"] = &v1alpha1.WorkloadPolicyRules{
		Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/cat", "/bin/echo"}},
	}
	wp.Spec.RulesByContainer["c3"] = &v1alpha1.WorkloadPolicyRules{
		Executables: v1alpha1.WorkloadPolicyExecutables{Allowed: []string{"/bin/ls"}},
	}
	require.NoError(t, r.handleWPUpdate(wp))
	state = r.wpState[key]
	require.Len(t, state, 2)
	require.NotContains(t, state, "c1")
	require.Equal(t, initialState["c2"], state["c2"], "c2 keeps its policy ID")
	require.Equal(t, PolicyID(3), state["c3"])

	// Delete
	require.NoError(t, r.handleWPDelete(wp))
	require.NotContains(t, r.wpState, key)
}
