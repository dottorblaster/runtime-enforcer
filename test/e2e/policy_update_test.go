package e2e_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getPolicyUpdateTest() types.Feature {
	workloadNamespace := envconf.RandomName("policy-update-ns", 32)

	return features.New("policy-update").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}

			err := r.Create(ctx, &namespace)
			assert.NoError(t, err, "failed to create test namespace")

			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.CreateOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to apply test data")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("policy update with new executables is enforced correctly",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				var podName string
				var pods corev1.PodList
				err := r.WithNamespace(workloadNamespace).List(ctx, &pods)
				require.NoError(t, err)

				for _, v := range pods.Items {
					if strings.HasPrefix(v.Name, "ubuntu-deployment") {
						podName = v.Name
						break
					}
				}
				require.NotEmpty(t, podName, "ubuntu pod not found")

				t.Log("creating initial policy with limited executables")
				policy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: workloadNamespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "protect",
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

				err = r.Create(ctx, &policy)
				require.NoError(t, err, "failed to create initial policy")

				waitForWorkloadPolicyStatusToBeUpdated()

				t.Log("verifying /usr/bin/cat is blocked before update")
				var stdout, stderr bytes.Buffer
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"ubuntu",
					[]string{"/usr/bin/cat", "/etc/hostname"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "/usr/bin/cat should be blocked")
				require.Contains(t, stderr.String(), "operation not permitted")

				t.Log("updating policy to add /usr/bin/cat")

				var updatedPolicy v1alpha1.WorkloadPolicy
				err = r.Get(ctx, "test-policy", workloadNamespace, &updatedPolicy)
				require.NoError(t, err, "failed to get policy for update")

				updatedPolicy.Spec.RulesByContainer["ubuntu"].Executables.Allowed = []string{
					"/usr/bin/ls",
					"/usr/bin/bash",
					"/usr/bin/sleep",
					"/usr/bin/cat",
				}

				err = r.Update(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to update policy")

				waitForWorkloadPolicyStatusToBeUpdated()

				t.Log("verifying /usr/bin/cat is allowed after update")
				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"ubuntu",
					[]string{"/usr/bin/cat", "/etc/hostname"},
					&stdout,
					&stderr,
				)
				require.NoError(t, err, "/usr/bin/cat should be allowed after policy update")
				require.NotEmpty(t, stdout.String(), "cat should have produced output")

				t.Log("verifying /usr/bin/apt is still blocked")
				stdout.Reset()
				stderr.Reset()
				err = r.ExecInPod(
					ctx,
					workloadNamespace,
					podName,
					"ubuntu",
					[]string{"/usr/bin/apt", "update"},
					&stdout,
					&stderr,
				)
				require.Error(t, err, "/usr/bin/apt should still be blocked")
				require.Contains(t, stderr.String(), "operation not permitted")

				t.Log("cleaning up policy")
				err = r.Delete(ctx, &updatedPolicy)
				require.NoError(t, err, "failed to delete policy")

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			r := ctx.Value(key("client")).(*resources.Resources)
			err := decoder.DeleteWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.DeleteOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}
