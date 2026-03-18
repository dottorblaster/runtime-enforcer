package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

// findPod is a utility function that calls k8s List API to find a pod with
// a specific prefix in a given namespace.
func findPod(ctx context.Context, namespace string, prefix string) (string, error) {
	var err error
	var pods corev1.PodList

	r := ctx.Value(key("client")).(*resources.Resources)

	err = r.WithNamespace(namespace).List(ctx, &pods)
	if err != nil {
		return "", err
	}

	for _, v := range pods.Items {
		if strings.HasPrefix(v.Name, prefix) {
			return v.Name, nil
		}
	}

	return "", errors.New("pod is not found")
}

func createWorkloadPolicy(ctx context.Context, t *testing.T, policy *v1alpha1.WorkloadPolicy) {
	r := ctx.Value(key("client")).(*resources.Resources)

	err := r.Create(ctx, policy)
	require.NoError(t, err, "create policy")

	waitForWorkloadPolicyStatusToBeUpdated(ctx, t, policy)
}

func deleteWorkloadPolicy(ctx context.Context, t *testing.T, policy *v1alpha1.WorkloadPolicy) {
	r := ctx.Value(key("client")).(*resources.Resources)

	err := r.Delete(ctx, policy)
	require.NoError(t, err)
}

func getMonitoringTest() types.Feature {
	return features.New("Monitoring").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			workloadNamespace := envconf.RandomName("monitoring-namespace", 32)

			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}

			err := r.Create(ctx, &namespace)
			require.NoError(t, err, "failed to create test namespace")

			return context.WithValue(ctx, key("namespace"), workloadNamespace)
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("setup policy")
			namespace := ctx.Value(key("namespace")).(string)

			policy := &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: namespace,
				},
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: "monitor",
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"ubuntu": {
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

			t.Log("creating workload policy and waiting for it to become Active")
			createWorkloadPolicy(ctx, t, policy.DeepCopy())
			return context.WithValue(ctx, key("policy"), policy.DeepCopy())
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")

			r := ctx.Value(key("client")).(*resources.Resources)
			namespace := ctx.Value(key("namespace")).(string)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.CreateOption{},
				getDeploymentPolicyMutateOption(namespace, "test-policy"),
			)
			require.NoError(t, err, "failed to apply test data")

			err = wait.For(
				conditions.New(r).DeploymentAvailable(
					"ubuntu-deployment",
					namespace,
				),
				wait.WithTimeout(DefaultOperationTimeout),
			)
			require.NoError(t, err)

			var ubuntuPodName string

			ubuntuPodName, err = findPod(ctx, namespace, "ubuntu-deployment")
			require.NoError(t, err)
			require.NotEmpty(t, ubuntuPodName)

			return context.WithValue(ctx, key("targetPodName"), ubuntuPodName)
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("a namespace-scoped policy can monitor behaviors correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				namespace := ctx.Value(key("namespace")).(string)
				expectedPodName := ctx.Value(key("targetPodName")).(string)
				r := ctx.Value(key("client")).(*resources.Resources)

				t.Log("executing allowed command (should not produce violations)")
				var stdout, stderr bytes.Buffer
				err := r.ExecInPod(ctx, namespace, expectedPodName, "ubuntu",
					[]string{"/usr/bin/ls"}, &stdout, &stderr)
				require.NoError(t, err)

				t.Log("executing disallowed command to trigger violation")
				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(ctx, namespace, expectedPodName, "ubuntu",
					[]string{"/usr/bin/sh", "-c", "/usr/bin/apt update"}, &stdout, &stderr)
				require.NoError(t, err)

				t.Log("waiting for violations to appear in WorkloadPolicy status")
				policyToCheck := &v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: namespace,
					},
				}
				err = wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
					wp, ok := obj.(*v1alpha1.WorkloadPolicy)
					if !ok {
						return false
					}
					if len(wp.Status.Violations) == 0 {
						return false
					}
					for _, v := range wp.Status.Violations {
						if v.ExecutablePath == "/usr/bin/apt" &&
							v.Action == policymode.MonitorString &&
							v.PodName == expectedPodName {
							return true
						}
					}
					return false
				}), wait.WithTimeout(DefaultOperationTimeout))
				require.NoError(t, err, "violation for /usr/bin/apt should appear in WorkloadPolicy status")

				t.Log("verifying violation record details")
				err = r.Get(ctx, "test-policy", namespace, policyToCheck)
				require.NoError(t, err)
				require.NotEmpty(t, policyToCheck.Status.Violations)

				var found bool
				for _, v := range policyToCheck.Status.Violations {
					if v.ExecutablePath == "/usr/bin/apt" {
						assert.Equal(t, policymode.MonitorString, v.Action)
						assert.Equal(t, expectedPodName, v.PodName)
						found = true
						break
					}
				}
				assert.True(t, found, "should find violation record for /usr/bin/apt")
				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			namespace := ctx.Value(key("namespace")).(string)
			r := ctx.Value(key("client")).(*resources.Resources)
			err := decoder.DeleteWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.DeleteOption{},
				decoder.MutateNamespace(namespace),
			)
			require.NoError(t, err, "failed to delete test data")

			policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
			t.Log("deleting test policy")
			deleteWorkloadPolicy(ctx, t, policy)

			return ctx
		}).Feature()
}
