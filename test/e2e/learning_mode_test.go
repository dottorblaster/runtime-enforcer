package e2e_test

import (
	"context"
	"os"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventhandler/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

func getLearningModeTest() types.Feature {
	workloadNamespace := envconf.RandomName("learning-namespace", 32)

	return features.New("LearningMode").
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
			t.Log("installing test resources")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"*",
				[]resources.CreateOption{},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to apply test data")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("the workload policy proposal is created successfully for each supported resource",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				testdata := os.DirFS("./testdata")

				testcases := map[string]struct {
					ParseFunc func() k8s.Object
				}{
					"DaemonSet": {
						ParseFunc: func() k8s.Object {
							var daemonset appsv1.DaemonSet
							err := decoder.DecodeFile(testdata, "ubuntu-daemonset.yaml", &daemonset)
							require.NoError(t, err)
							return &daemonset
						},
					},
					"Deployment": {
						ParseFunc: func() k8s.Object {
							var deployment appsv1.Deployment
							err := decoder.DecodeFile(testdata, "ubuntu-deployment.yaml", &deployment)
							require.NoError(t, err)
							return &deployment
						},
					},
					"StatefulSet": {
						ParseFunc: func() k8s.Object {
							var statefulset appsv1.StatefulSet
							err := decoder.DecodeFile(testdata, "ubuntu-statefulset.yaml", &statefulset)
							require.NoError(t, err)
							return &statefulset
						},
					},
					"Job": {
						ParseFunc: func() k8s.Object {
							var job batchv1.Job
							err := decoder.DecodeFile(testdata, "ubuntu-job.yaml", &job)
							require.NoError(t, err)
							return &job
						},
					},
					"CronJob": {
						ParseFunc: func() k8s.Object {
							var cronjob batchv1.CronJob
							err := decoder.DecodeFile(testdata, "ubuntu-cronjob.yaml", &cronjob)
							require.NoError(t, err)
							return &cronjob
						},
					},
				}

				for kind, tc := range testcases {
					obj := tc.ParseFunc()
					t.Log("verifying if a proposal resource can be created: ", kind)

					proposalName, err := utils.GetWorkloadPolicyProposalName(kind, obj.GetName())
					require.NoError(t, err)

					proposal := v1alpha1.WorkloadPolicyProposal{
						ObjectMeta: metav1.ObjectMeta{
							Name:      proposalName,
							Namespace: workloadNamespace, // to be consistent with test data.
						},
					}
					err = wait.For(conditions.New(r).ResourceMatch(
						&proposal,
						func(_ k8s.Object) bool {
							return true
						}),
						wait.WithTimeout(DefaultOperationTimeout),
					)
					require.NoError(t, err)
					require.Len(t, proposal.OwnerReferences, 1)
					require.Equal(t, obj.GetName(), proposal.OwnerReferences[0].Name)
					require.Equal(t, obj.GetObjectKind().GroupVersionKind().Kind, proposal.OwnerReferences[0].Kind)

					t.Log("verifying if processes can be learned")
					err = wait.For(conditions.New(r).ResourceMatch(
						&proposal,
						func(_ k8s.Object) bool {
							if proposal.Spec.RulesByContainer == nil {
								return false
							}

							t.Log("proposal: ", proposal)

							rules, ok := proposal.Spec.RulesByContainer["ubuntu"]
							if !ok {
								return false
							}

							return verifyUbuntuLearnedProcesses(rules.Executables.Allowed)
						}),
						wait.WithTimeout(DefaultOperationTimeout),
					)
					require.NoError(t, err)
				}

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.DeleteWithManifestDir(
				ctx,
				r,
				"./testdata",
				"*",
				[]resources.DeleteOption{
					resources.WithDeletePropagation("Foreground"),
				},
				decoder.MutateNamespace(workloadNamespace),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}

func getLearningModeNamespaceSelectorTest() types.Feature {
	enabledNS := envconf.RandomName("learning-enabled-ns", 32)
	disabledNS := envconf.RandomName("learning-disabled-ns", 32)
	const deploymentName = "ubuntu-deployment"

	return features.New("LearningModeNamespaceSelector").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("enabling learning namespace selector env=e2e-test for this test only")

			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunUpgrade(
				helm.WithName("runtime-enforcer"),
				helm.WithNamespace(runtimeEnforcerNamespace),
				helm.WithChart("../../charts/runtime-enforcer/"),
				helm.WithArgs("--reuse-values"),
				helm.WithArgs("--set", "learning.namespaceSelector=env=e2e-test"),
				helm.WithWait(),
				helm.WithTimeout(DefaultHelmTimeout.String()),
			)
			require.NoError(t, err, "failed to enable learning namespace selector for test")

			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log(
				"creating namespaces: one with selector label (should be learned), one without (should not be learned)",
				"enabledNS: ", enabledNS,
				"disabledNS: ", disabledNS,
			)
			r := ctx.Value(key("client")).(*resources.Resources)
			enabled := corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   enabledNS,
					Labels: map[string]string{"env": "e2e-test"},
				},
			}
			disabled := corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: disabledNS},
			}
			require.NoError(t, r.Create(ctx, &enabled))
			require.NoError(t, r.Create(ctx, &disabled))
			return ctx
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing deployment in both namespaces")
			r := ctx.Value(key("client")).(*resources.Resources)
			for _, ns := range []string{enabledNS, disabledNS} {
				err := decoder.ApplyWithManifestDir(
					ctx,
					r,
					"./testdata",
					"ubuntu-deployment.yaml",
					[]resources.CreateOption{},
					decoder.MutateNamespace(ns),
				)
				require.NoError(t, err, "failed to apply test data in namespace %s", ns)
			}
			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("learning creates WorkloadPolicyProposal only in the labeled namespace", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := ctx.Value(key("client")).(*resources.Resources)

			proposalName, err := utils.GetWorkloadPolicyProposalName("Deployment", deploymentName)
			require.NoError(t, err)

			t.Log("verifying proposal is created and learns in the learning-enabled namespace")
			proposalInEnabled := v1alpha1.WorkloadPolicyProposal{
				ObjectMeta: metav1.ObjectMeta{
					Name:      proposalName,
					Namespace: enabledNS,
				},
			}
			err = wait.For(conditions.New(r).ResourceMatch(
				&proposalInEnabled,
				func(obj k8s.Object) bool {
					p, ok := obj.(*v1alpha1.WorkloadPolicyProposal)
					if !ok || p.Spec.RulesByContainer == nil {
						return false
					}
					rules, ok := p.Spec.RulesByContainer["ubuntu"]
					return ok && verifyUbuntuLearnedProcesses(rules.Executables.Allowed)
				}),
				wait.WithTimeout(DefaultOperationTimeout),
			)
			require.NoError(
				t,
				err,
				"expected WorkloadPolicyProposal to be created and learn in namespace %s",
				enabledNS,
			)

			t.Log("verifying no managed WorkloadPolicyProposal exists in the learning-disabled namespace")
			var list v1alpha1.WorkloadPolicyProposalList
			err = r.WithNamespace(disabledNS).List(ctx, &list)
			require.NoError(t, err)
			require.Empty(
				t, list.Items,
				"expected no WorkloadPolicyProposals in namespace %s (selector should exclude it)",
				disabledNS,
			)

			return ctx
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			r := ctx.Value(key("client")).(*resources.Resources)

			for _, ns := range []string{enabledNS, disabledNS} {
				err := r.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
				require.NoError(t, err, "failed to delete namespace %s", ns)
			}

			t.Log("disabling learning namespace selector after test")
			manager := helm.New(cfg.KubeconfigFile())
			err := manager.RunUpgrade(
				helm.WithName("runtime-enforcer"),
				helm.WithNamespace(runtimeEnforcerNamespace),
				helm.WithChart("../../charts/runtime-enforcer/"),
				helm.WithArgs("--reuse-values"),
				helm.WithArgs("--set", "learning.namespaceSelector="),
				helm.WithWait(),
				helm.WithTimeout(DefaultHelmTimeout.String()),
			)
			require.NoError(t, err, "failed to disable learning namespace selector after test")

			return ctx
		}).Feature()
}
