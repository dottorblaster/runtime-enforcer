package e2e_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	apimachinerywait "k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/e2e-framework/klient/decoder"
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

func getDeploymentPolicyMutateOption(
	namespace string,
	policy string, //nolint:unparam // we want to keep the flexibility to support different policy name.
) decoder.DecodeOption {
	// Support only deployment right now.
	return decoder.MutateOption(func(obj k8s.Object) error {
		deployment := obj.(*appsv1.Deployment)
		deployment.SetNamespace(namespace)
		deployment.Spec.Template.Labels[v1alpha1.PolicyLabelKey] = policy
		return nil
	})
}

func daemonSetUpToDate(r *resources.Resources, daemonset *appsv1.DaemonSet) apimachinerywait.ConditionWithContextFunc {
	return func(ctx context.Context) (bool, error) {
		if err := r.Get(ctx, daemonset.GetName(), daemonset.GetNamespace(), daemonset); err != nil {
			return false, err
		}
		status := daemonset.Status
		if status.UpdatedNumberScheduled != status.DesiredNumberScheduled {
			return false, nil
		}
		return true, nil
	}
}

func deploymentUpToDate(
	r *resources.Resources,
	deployment *appsv1.Deployment,
) apimachinerywait.ConditionWithContextFunc {
	return func(ctx context.Context) (bool, error) {
		if err := r.Get(ctx, deployment.GetName(), deployment.GetNamespace(), deployment); err != nil {
			return false, err
		}
		status := deployment.Status
		if status.Replicas != *deployment.Spec.Replicas {
			return false, nil
		}
		if status.UpdatedReplicas != status.Replicas {
			return false, nil
		}
		return true, nil
	}
}
