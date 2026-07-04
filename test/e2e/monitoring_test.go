package e2e_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getMonitoringTest() types.Feature {
	return features.New("Monitoring").
		Setup(SetupSharedK8sClient).
		Setup(SetupTestNamespace).
		Setup(setupMonitoringPolicy).
		Setup(setupMonitoringDeployment).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("allowed command produces no violation", assessMonitoringAllowedCommand).
		Assess("trigger a violation in monitor mode", assessMonitoringTriggerViolation).
		Assess("violation appears in WorkloadPolicy status", assessMonitoringWaitForViolation).
		Assess("acknowledge the violation via annotation", assessAcknowledgeAnnotate).
		Assess("violation is moved to acknowledged violations", assessAcknowledgeVerify).
		Teardown(teardownMonitoring).
		Feature()
}

func setupMonitoringPolicy(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	policy := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: getNamespace(ctx),
		},
		Spec: v1alpha1.WorkloadPolicySpec{
			Mode: policymode.MonitorString,
			RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
				"opensuse": {
					Executables: v1alpha1.WorkloadPolicyExecutables{
						Allowed: []string{
							"/usr/bin/ls",
							"/usr/bin/bash",
							"/usr/bin/sleep",
						},
					},
				},
			},
		},
	}
	createAndWaitWP(ctx, t, policy.DeepCopy())
	return context.WithValue(ctx, key("policy"), policy.DeepCopy())
}

func setupMonitoringDeployment(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	createAndWaitOpensuseDeployment(ctx, t, withPolicy("test-policy"))
	opensusePodName, err := findOpensuseDeploymentPod(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, opensusePodName)
	return context.WithValue(ctx, key("targetPodName"), opensusePodName)
}

func assessMonitoringAllowedCommand(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	targetPodName := ctx.Value(key("targetPodName")).(string)
	t.Log("executing allowed command (should not produce violations)")
	requireExecAllowedInCurrentNamespace(ctx, t, targetPodName, "opensuse", []string{"/usr/bin/ls"})
	return ctx
}

func assessMonitoringTriggerViolation(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	targetPodName := ctx.Value(key("targetPodName")).(string)
	t.Log("executing disallowed command to trigger violation")
	requireExecAllowedInCurrentNamespace(
		ctx,
		t,
		targetPodName,
		"opensuse",
		[]string{"/usr/bin/sh", "-c", "/usr/bin/zypper refresh"},
	)
	return ctx
}

func assessMonitoringWaitForViolation(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	targetPodName := ctx.Value(key("targetPodName")).(string)
	r := getClient(ctx)

	policyToCheck := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: getNamespace(ctx),
		},
	}

	t.Log("waiting for zypper violation to appear in WorkloadPolicy status")
	err := wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
		wp, ok := obj.(*v1alpha1.WorkloadPolicy)
		if !ok {
			return false
		}
		for _, v := range wp.Status.Violations {
			if v.ExecutablePath == "/usr/bin/zypper" && v.PodName == targetPodName {
				return true
			}
		}
		return false
	}), wait.WithTimeout(defaultOperationTimeout))
	require.NoError(t, err, "violation for /usr/bin/zypper should appear in WorkloadPolicy status")

	err = r.Get(ctx, "test-policy", getNamespace(ctx), policyToCheck)
	require.NoError(t, err)

	var violationID int64
	var found bool
	for _, v := range policyToCheck.Status.Violations {
		if v.ExecutablePath == "/usr/bin/zypper" {
			assert.Equal(t, policymode.MonitorString, v.Action)
			assert.Equal(t, targetPodName, v.PodName)
			violationID = v.ID
			found = true
			break
		}
	}
	assert.True(t, found, "should find violation record for /usr/bin/zypper")

	return context.WithValue(ctx, key("violationID"), violationID)
}

func assessAcknowledgeAnnotate(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	r := getClient(ctx)
	violationID := ctx.Value(key("violationID")).(int64)

	policy := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: getNamespace(ctx),
		},
	}
	err := r.Get(ctx, "test-policy", getNamespace(ctx), policy)
	require.NoError(t, err)

	if policy.Annotations == nil {
		policy.Annotations = make(map[string]string)
	}
	policy.Annotations[v1alpha1.ViolationAcknowledgePrefix+strconv.FormatInt(violationID, 10)] = "e2e test acknowledgement"

	err = r.Update(ctx, policy)
	require.NoError(t, err, "failed to annotate WorkloadPolicy to acknowledge violation")
	return ctx
}

func assessAcknowledgeVerify(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	r := getClient(ctx)
	violationID := ctx.Value(key("violationID")).(int64)

	policyToCheck := &v1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: getNamespace(ctx),
		},
	}

	t.Log("waiting for violation to appear in acknowledgedViolations")
	err := wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
		wp, ok := obj.(*v1alpha1.WorkloadPolicy)
		if !ok {
			return false
		}
		for _, av := range wp.Status.AcknowledgedViolations {
			if av.Violation.ID == violationID {
				return true
			}
		}
		return false
	}), wait.WithTimeout(defaultOperationTimeout))
	require.NoError(t, err, "violation should be moved to acknowledgedViolations")

	err = r.Get(ctx, "test-policy", getNamespace(ctx), policyToCheck)
	require.NoError(t, err)

	var found bool
	for _, av := range policyToCheck.Status.AcknowledgedViolations {
		if av.Violation.ID == violationID {
			assert.Equal(t, "e2e test acknowledgement", av.Reason)
			assert.False(t, av.AcknowledgedAt.IsZero(), "acknowledgedAt should be non-zero")
			found = true
			break
		}
	}
	assert.True(t, found, "acknowledged violation record should be present")

	for _, v := range policyToCheck.Status.Violations {
		assert.NotEqual(t, violationID, v.ID, "violation should no longer be in status.violations")
	}

	annotationKey := v1alpha1.ViolationAcknowledgePrefix + strconv.FormatInt(violationID, 10)
	_, annotationPresent := policyToCheck.Annotations[annotationKey]
	assert.False(t, annotationPresent, "acknowledge annotation should be removed after processing")

	return ctx
}

func teardownMonitoring(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	deleteOpensuseDeployment(ctx, t)
	policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
	deleteAndWaitWP(ctx, t, policy)
	return ctx
}
