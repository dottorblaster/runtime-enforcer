package e2e_test

import (
	"context"
	"strings"
	"testing"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getValidatingAdmissionPolicyPodPolicyLabelTest() types.Feature {
	workloadNamespace := envconf.RandomName("vap-test-ns", 32)

	return features.New("Test ValidatingAdmissionPolicy for Pod policy label").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}

			err := r.Create(ctx, &namespace)
			assert.NoError(t, err, "failed to create test namespace")

			return ctx
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("VAP prevents adding policy label to existing pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				// Create a pod without the policy label
				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-no-label",
						Namespace: workloadNamespace,
						Labels: map[string]string{
							"app": "test",
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

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create pod without label")

				// Wait for pod to be running to reduce status update conflicts
				err = wait.For(
					conditions.New(r).PodRunning(&pod),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "pod failed to reach running state")
				var createdPod corev1.Pod
				err = r.Get(ctx, "test-pod-no-label", workloadNamespace, &createdPod)
				require.NoError(t, err, "failed to get created pod")

				// Try to add the policy label - this should be rejected by VAP
				createdPod.Labels[v1alpha1.PolicyLabelKey] = "test-policy"
				err = r.Update(ctx, &createdPod)
				require.Error(t, err, "VAP should have rejected adding the policy label")
				require.True(t, errors.IsInvalid(err) || errors.IsForbidden(err),
					"expected Invalid or Forbidden error, got: %v", err)

				// Verify the label was not added
				var updatedPod corev1.Pod
				err = r.Get(ctx, "test-pod-no-label", workloadNamespace, &updatedPod)
				require.NoError(t, err, "failed to get pod after failed update")
				_, exists := updatedPod.Labels[v1alpha1.PolicyLabelKey]
				require.False(t, exists, "policy label should not exist on pod")

				// Clean up
				err = r.Delete(ctx, &pod)
				assert.NoError(t, err, "failed to delete pod")

				return ctx
			}).
		Assess("VAP prevents removing policy label from existing pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				// Create a pod with the policy label
				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-with-label",
						Namespace: workloadNamespace,
						Labels: map[string]string{
							"app":                   "test",
							v1alpha1.PolicyLabelKey: "test-policy",
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

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create pod with label")

				// Wait for pod to be running to reduce status update conflicts
				err = wait.For(
					conditions.New(r).PodRunning(&pod),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "pod failed to reach running state")
				var createdPod corev1.Pod
				err = r.Get(ctx, "test-pod-with-label", workloadNamespace, &createdPod)
				require.NoError(t, err, "failed to get created pod")

				// Try to remove the policy label - this should be rejected by VAP
				delete(createdPod.Labels, v1alpha1.PolicyLabelKey)
				err = r.Update(ctx, &createdPod)
				require.Error(t, err, "VAP should have rejected removing the policy label")
				require.True(t, errors.IsInvalid(err) || errors.IsForbidden(err),
					"expected Invalid or Forbidden error, got: %v", err)

				// Verify the label still exists
				var updatedPod corev1.Pod
				err = r.Get(ctx, "test-pod-with-label", workloadNamespace, &updatedPod)
				require.NoError(t, err, "failed to get pod after failed update")
				labelValue, exists := updatedPod.Labels[v1alpha1.PolicyLabelKey]
				require.True(t, exists, "policy label should still exist on pod")
				require.Equal(t, "test-policy", labelValue, "policy label value should be unchanged")

				// Clean up
				err = r.Delete(ctx, &pod)
				assert.NoError(t, err, "failed to delete pod")

				return ctx
			}).
		Assess("VAP prevents changing policy label value on existing pod",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				// Create a pod with the policy label
				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-change-label",
						Namespace: workloadNamespace,
						Labels: map[string]string{
							"app":                   "test",
							v1alpha1.PolicyLabelKey: "original-policy",
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

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create pod with label")

				// Wait for pod to be running to reduce status update conflicts
				err = wait.For(
					conditions.New(r).PodRunning(&pod),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "pod failed to reach running state")
				var createdPod corev1.Pod
				err = r.Get(ctx, "test-pod-change-label", workloadNamespace, &createdPod)
				require.NoError(t, err, "failed to get created pod")

				// Try to change the policy label value - this should be rejected by VAP
				createdPod.Labels[v1alpha1.PolicyLabelKey] = "new-policy"
				err = r.Update(ctx, &createdPod)
				require.Error(t, err, "VAP should have rejected changing the policy label value")
				require.True(t, errors.IsInvalid(err) || errors.IsForbidden(err),
					"expected Invalid or Forbidden error, got: %v", err)

				// Verify the label value was not changed
				var updatedPod corev1.Pod
				err = r.Get(ctx, "test-pod-change-label", workloadNamespace, &updatedPod)
				require.NoError(t, err, "failed to get pod after failed update")
				labelValue, exists := updatedPod.Labels[v1alpha1.PolicyLabelKey]
				require.True(t, exists, "policy label should still exist on pod")
				require.Equal(t, "original-policy", labelValue, "policy label value should be unchanged")

				// Clean up
				err = r.Delete(ctx, &pod)
				assert.NoError(t, err, "failed to delete pod")

				return ctx
			}).
		Assess("Updating other Pod fields should be allowed when policy label exists",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				// Create a pod with the policy label
				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-with-label-update-fields",
						Namespace: workloadNamespace,
						Labels: map[string]string{
							"app":                   "test",
							v1alpha1.PolicyLabelKey: "test-policy",
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

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create pod with policy label")

				// Wait for pod to be running to reduce status update conflicts
				err = wait.For(
					conditions.New(r).PodRunning(&pod),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "pod failed to reach running state")
				var createdPod corev1.Pod
				err = r.Get(ctx, "test-pod-with-label-update-fields", workloadNamespace, &createdPod)
				require.NoError(t, err, "failed to get created pod")

				// Update other pod fields - this should be allowed
				if createdPod.Annotations == nil {
					createdPod.Annotations = make(map[string]string)
				}
				createdPod.Annotations["test-annotation"] = "test-value"
				createdPod.Labels["other-label"] = "other-value"
				err = r.Update(ctx, &createdPod)
				require.NoError(t, err, "Updating other pod fields when policy label exists should be allowed")

				// Verify the policy label is unchanged
				var updatedPod corev1.Pod
				err = r.Get(ctx, "test-pod-with-label-update-fields", workloadNamespace, &updatedPod)
				require.NoError(t, err, "failed to get pod after update")
				labelValue, exists := updatedPod.Labels[v1alpha1.PolicyLabelKey]
				require.True(t, exists, "policy label should still exist on pod")
				require.Equal(t, "test-policy", labelValue, "policy label value should be unchanged")
				require.Equal(
					t,
					"test-value",
					updatedPod.Annotations["test-annotation"],
					"annotation should be updated",
				)
				require.Equal(
					t,
					"other-value",
					updatedPod.Labels["other-label"],
					"other label should be updated",
				)

				// Clean up
				err = r.Delete(ctx, &pod)
				assert.NoError(t, err, "failed to delete pod")

				return ctx
			}).
		Assess("Updating other Pod fields should be allowed when policy label does not exist",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				// Create a pod without the policy label
				pod := corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod-no-label-update-fields",
						Namespace: workloadNamespace,
						Labels: map[string]string{
							"app": "test",
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

				err := r.Create(ctx, &pod)
				require.NoError(t, err, "failed to create pod without policy label")

				// Wait for pod to be running to reduce status update conflicts
				err = wait.For(
					conditions.New(r).PodRunning(&pod),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "pod failed to reach running state")
				var createdPod corev1.Pod
				err = r.Get(ctx, "test-pod-no-label-update-fields", workloadNamespace, &createdPod)
				require.NoError(t, err, "failed to get created pod")

				// Update other pod fields - this should be allowed
				if createdPod.Annotations == nil {
					createdPod.Annotations = make(map[string]string)
				}
				createdPod.Annotations["test-annotation"] = "test-value"
				createdPod.Labels["other-label"] = "other-value"

				err = r.Update(ctx, &createdPod)
				require.NoError(t, err, "Updating other pod fields when policy label does not exist should be allowed")

				// Verify the pod was updated and policy label still doesn't exist
				var updatedPod corev1.Pod
				err = r.Get(ctx, "test-pod-no-label-update-fields", workloadNamespace, &updatedPod)
				require.NoError(t, err, "failed to get pod after update")
				_, exists := updatedPod.Labels[v1alpha1.PolicyLabelKey]
				require.False(t, exists, "policy label should not exist on pod")
				require.Equal(
					t,
					"test-value",
					updatedPod.Annotations["test-annotation"],
					"annotation should be updated",
				)
				require.Equal(
					t,
					"other-value",
					updatedPod.Labels["other-label"],
					"other label should be updated",
				)

				// Clean up
				err = r.Delete(ctx, &pod)
				assert.NoError(t, err, "failed to delete pod")

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("cleaning up test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			// Clean up any remaining pods
			var pods corev1.PodList
			err := r.WithNamespace(workloadNamespace).List(ctx, &pods)
			if err == nil {
				for _, pod := range pods.Items {
					if strings.HasPrefix(pod.Name, "test-pod-") {
						_ = r.Delete(ctx, &pod)
					}
				}
			}

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}
			err = r.Delete(ctx, &namespace)
			assert.NoError(t, err, "failed to delete test namespace")

			return ctx
		}).Feature()
}
