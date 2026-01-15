package e2e_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/policygenerator"
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

func getMainTest() types.Feature {
	workloadNamespace := envconf.RandomName("main-namespace", 32)

	return features.New("Main").
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
		Assess("the workload policy proposal is created successfully for the ubuntu pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				proposal := v1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deploy-ubuntu-deployment",
						Namespace: workloadNamespace, // to be consistent with test data.
					},
				}
				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(object k8s.Object) bool {
						obj := object.(*v1alpha1.WorkloadPolicyProposal)
						if obj.OwnerReferences[0].Name == "ubuntu-deployment" &&
							obj.OwnerReferences[0].Kind == "Deployment" {
							return true
						}
						return false
					}),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("group"), proposal.Name)
			}).
		Assess("the running process is learned",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				id := ctx.Value(key("group")).(string)
				r := ctx.Value(key("client")).(*resources.Resources)

				t.Log("waiting for workload policy proposal to be created: ", id)

				proposal := v1alpha1.WorkloadPolicyProposal{
					ObjectMeta: metav1.ObjectMeta{
						Name:      id,
						Namespace: workloadNamespace, // to be consistent with test data.
					},
				}

				// There are two categories of processes to be learned:
				// 1. /usr/bin/bash: the container entrypoint.
				// 2. /usr/bin/sleep & /usr/bin/ls: the commands the container executes
				t.Log("waiting for processes to be learned")

				err := wait.For(conditions.New(r).ResourceMatch(
					&proposal,
					func(_ k8s.Object) bool {
						rules := proposal.Spec.RulesByContainer["ubuntu"]

						return verifyUbuntuLearnedProcesses(rules.Executables.Allowed)
					}),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err)

				return context.WithValue(ctx, key("proposal"), &proposal)
			}).
		Assess("a proposal is promoted to a workload policy and the WP is created",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				t.Log("create a workload policy")

				r := ctx.Value(key("client")).(*resources.Resources)
				proposal := ctx.Value(key("proposal")).(*v1alpha1.WorkloadPolicyProposal)

				policy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: proposal.ObjectMeta.Namespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode:     "protect",
						Selector: proposal.Spec.Selector,
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed:         proposal.Spec.RulesByContainer["ubuntu"].Executables.Allowed,
									AllowedPrefixes: proposal.Spec.RulesByContainer["ubuntu"].Executables.AllowedPrefixes,
								},
							},
						},
					},
				}
				err := r.Create(ctx, &policy)
				require.NoError(t, err, "create policy")

				// todo!: we should check the status of the WP is updated

				return context.WithValue(ctx, key("policy"), &policy)
			}).
		Assess("pod exec will be blocked",
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

				var stdout, stderr bytes.Buffer

				err = r.ExecInPod(ctx, workloadNamespace, podName, "ubuntu", []string{"mkdir"}, &stdout, &stderr)
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Equal(t, "exec /usr/bin/mkdir: operation not permitted\n", stderr.String())

				return ctx
			}).
		Assess("the WorkloadPolicy has the finalizer set",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)
				policy := &v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: workloadNamespace,
					},
				}

				err := wait.For(
					conditions.New(r).ResourceMatch(
						policy,
						func(obj k8s.Object) bool {
							wp := obj.(*v1alpha1.WorkloadPolicy)
							return slices.Contains(wp.Finalizers, v1alpha1.WorkloadPolicyFinalizer)
						},
					),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "WorkloadPolicy finalizer is not set")

				return ctx
			}).
		Assess("Verify a non-referenced WorkloadPolicy can be deleted",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var err error
				r := ctx.Value(key("client")).(*resources.Resources)
				nonReferencedPolicyName := "non-referenced-wp"

				// Create a new WorkloadPolicy
				nonReferencedPolicy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      nonReferencedPolicyName,
						Namespace: workloadNamespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "monitor",
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{"/bin/true"},
								},
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &nonReferencedPolicy),
					"failed to create non-referenced WorkloadPolicy",
				)

				err = r.Delete(ctx, &nonReferencedPolicy)
				require.NoError(t, err, "failed to delete non-referenced WorkloadPolicy")

				// Wait for the WorkloadPolicy to be deleted
				err = wait.For(
					conditions.New(r).ResourceDeleted(&nonReferencedPolicy),
					wait.WithTimeout(time.Minute*2),
					wait.WithInterval(time.Second*5),
				)
				require.NoError(
					t,
					err,
					"policy was not deleted within timeout",
				)

				return ctx
			}).
		Assess("Verify a referenced WorkloadPolicy cannot be deleted",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				var err error
				r := ctx.Value(key("client")).(*resources.Resources)
				referencedPolicyName := "referenced-wp"
				podName := "referenced-wp-pod"

				// Create a new WorkloadPolicy
				referencedPolicy := v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      referencedPolicyName,
						Namespace: workloadNamespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "monitor",
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{"/bin/true"},
								},
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &referencedPolicy),
					"failed to create referenced WorkloadPolicy",
				)

				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName,
						Namespace: workloadNamespace,
						Labels: map[string]string{
							policygenerator.PolicyLabelKey: referencedPolicyName,
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "pause",
								Image: "registry.k8s.io/pause",
							},
						},
					},
				}
				require.NoError(
					t,
					r.Create(ctx, &pod),
					"failed to create Pod",
				)

				// Try to delete the referenced policy
				require.NoError(
					t,
					r.Delete(ctx, &referencedPolicy),
					"failed to issue delete request for WorkloadPolicy",
				)

				// Verify the policy still exists (should not be deleted due to finalizer)
				err = wait.For(
					conditions.New(r).ResourceMatch(
						&referencedPolicy,
						func(obj k8s.Object) bool {
							wp := obj.(*v1alpha1.WorkloadPolicy)
							return wp.DeletionTimestamp != nil &&
								slices.Contains(wp.Finalizers, v1alpha1.WorkloadPolicyFinalizer)
						},
					),
					wait.WithTimeout(30*time.Second),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"WorkloadPolicy should still exist while referenced by Pod",
				)

				// Clean up pod, then policy should be deleted automatically
				require.NoError(
					t,
					r.Delete(ctx, &pod),
					"failed to delete Pod",
				)

				// Wait for the pod to be deleted
				err = wait.For(
					conditions.New(r).ResourceDeleted(&pod),
					wait.WithTimeout(2*time.Minute),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"Pod was not deleted within timeout",
				)

				// Now the policy should be deleted automatically
				err = wait.For(
					conditions.New(r).ResourceDeleted(&referencedPolicy),
					wait.WithTimeout(2*time.Minute),
					wait.WithInterval(5*time.Second),
				)
				require.NoError(
					t,
					err,
					"WorkloadPolicy should be deleted after Pod is removed",
				)

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
