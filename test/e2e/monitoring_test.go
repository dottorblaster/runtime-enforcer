package e2e_test

import (
	"context"
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
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
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
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createAndWaitOpensuseDeployment(ctx, t, withPolicy("test-policy"))
			opensusePodName, err := findOpensuseDeploymentPod(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, opensusePodName)
			return context.WithValue(ctx, key("targetPodName"), opensusePodName)
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("a namespace-scoped policy can monitor behaviors correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				expectedPodName := ctx.Value(key("targetPodName")).(string)
				r := getClient(ctx)
				var err error

				t.Log("executing allowed command (should not produce violations)")
				requireExecAllowedInCurrentNamespace(ctx, t, expectedPodName, "opensuse", []string{"/usr/bin/ls"})

				t.Log("executing disallowed command to trigger violation")
				requireExecAllowedInCurrentNamespace(
					ctx,
					t,
					expectedPodName,
					"opensuse",
					[]string{"/usr/bin/sh", "-c", "/usr/bin/zypper refresh"},
				)

				t.Log("waiting for violations to appear in WorkloadPolicy status")
				policyToCheck := &v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: getNamespace(ctx),
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
						if v.ExecutablePath == "/usr/bin/zypper" &&
							v.Action == policymode.MonitorString &&
							v.PodName == expectedPodName {
							return true
						}
					}
					return false
				}), wait.WithTimeout(defaultOperationTimeout))
				require.NoError(t, err, "violation for /usr/bin/zypper should appear in WorkloadPolicy status")

				t.Log("verifying violation record details")
				err = r.Get(ctx, "test-policy", getNamespace(ctx), policyToCheck)
				require.NoError(t, err)
				require.NotEmpty(t, policyToCheck.Status.Violations)

				var found bool
				for _, v := range policyToCheck.Status.Violations {
					if v.ExecutablePath == "/usr/bin/zypper" {
						assert.Equal(t, policymode.MonitorString, v.Action)
						assert.Equal(t, expectedPodName, v.PodName)
						found = true
						break
					}
				}
				assert.True(t, found, "should find violation record for /usr/bin/zypper")
				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteOpensuseDeployment(ctx, t)
			policy := ctx.Value(key("policy")).(*v1alpha1.WorkloadPolicy)
			deleteAndWaitWP(ctx, t, policy)
			return ctx
		}).Feature()
}
