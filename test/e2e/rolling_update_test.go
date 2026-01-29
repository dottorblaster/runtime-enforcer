package e2e_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
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

// This test verifis the protection is persistent during rolling update of agent.
func getRollingUpdateTest() types.Feature {
	workloadNamespace := envconf.RandomName("workload-namespace", 32)

	return features.New("Rolling update").
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
			r := ctx.Value(key("client")).(*resources.Resources)

			err := r.Create(ctx, &v1alpha1.WorkloadPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: workloadNamespace,
				},
				Spec: v1alpha1.WorkloadPolicySpec{
					Mode: "protect",
					RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
						"ubuntu": &v1alpha1.WorkloadPolicyRules{
							Executables: v1alpha1.WorkloadPolicyExecutables{
								Allowed: []string{
									"/usr/bin/bash",
									"/usr/bin/ls",
								},
							},
						},
					},
				},
			})
			require.NoError(t, err, "failed to create workload namespace")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")

			r := ctx.Value(key("client")).(*resources.Resources)

			err := decoder.ApplyWithManifestDir(
				ctx,
				r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.CreateOption{},
				decoder.MutateOption(func(obj k8s.Object) error {
					deployment := obj.(*appsv1.Deployment)
					deployment.Namespace = workloadNamespace
					deployment.Spec.Template.Spec.Containers[0].Command = []string{
						"bash",
						"-c",
						"while true; do mkdir /tmp/testdir;done", // this command is supposed to be failing throughout rolling update.
					}
					deployment.Spec.Template.Labels[v1alpha1.PolicyLabelKey] = "test-policy"
					return nil
				}),
			)
			assert.NoError(t, err, "failed to apply test data")

			return ctx
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
				require.Contains(t, stderr.String(), "operation not permitted\n")
				return ctx
			}).
		Assess("rolling update should succeed", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			r := ctx.Value(key("client")).(*resources.Resources)
			agentDaemonSet := appsv1.DaemonSet{}
			err := r.Get(
				ctx,
				"runtime-enforcer-agent",
				namespace,
				&agentDaemonSet,
			)
			require.NoError(t, err)
			agentDaemonSet.Spec.Template.Labels["restart"] = "restart" // trigger rolling update

			err = r.Update(ctx, &agentDaemonSet)
			require.NoError(t, err)

			err = wait.For(conditions.New(r).DaemonSetReady(
				&appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "runtime-enforcer-agent",
						Namespace: namespace,
					},
				}),
				wait.WithTimeout(DefaultOperationTimeout),
			)
			require.NoError(t, err)
			return ctx
		}).
		Assess("/tmp/testdir should never be created", func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
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

			err = r.ExecInPod(
				ctx,
				workloadNamespace,
				podName,
				"ubuntu",
				[]string{"ls", "/tmp/testdir"},
				&stdout,
				&stderr,
			)
			t.Log("getting result", err, stdout, stderr)
			require.Error(t, err)
			require.Empty(t, stdout.String())
			require.Contains(t, stderr.String(), "No such file or directory\n")
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
