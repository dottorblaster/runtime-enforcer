package e2e_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
)

func waitForWorkloadPolicyStatusToBeUpdated(
	ctx context.Context,
	t *testing.T,
	policy *v1alpha1.WorkloadPolicy,
) {
	r := ctx.Value(key("client")).(*resources.Resources)
	err := wait.For(conditions.New(r).ResourceMatch(policy, func(obj k8s.Object) bool {
		ps, ok := obj.(*v1alpha1.WorkloadPolicy)
		if !ok {
			return false
		}
		t.Log("checking workloadpolicy status:", ps.Status)
		if ps.Status.ObservedGeneration != ps.Generation {
			return false
		}
		// todo!: at the moment the agent only sends a mock state `protect`
		// so this method can be only used for checking protection
		if ps.Status.Phase != v1alpha1.Active {
			return false
		}
		if len(ps.Status.NodesTransitioning) != 0 {
			return false
		}
		if len(ps.Status.NodesWithIssues) != 0 {
			return false
		}
		return true
	}), wait.WithTimeout(15*time.Second))
	require.NoError(t, err, "workloadpolicy status should be updated to Deployed")
}

func verifyUbuntuLearnedProcesses(values []string) bool {
	return slices.Contains(values, "/usr/bin/bash") &&
		slices.Contains(values, "/usr/bin/ls") &&
		slices.Contains(values, "/usr/bin/sleep")
}
