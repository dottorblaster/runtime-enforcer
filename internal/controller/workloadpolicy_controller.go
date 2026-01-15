package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	PolicyDeletionRequeueDelay = 90 * time.Second
)

// WorkloadPolicyReconciler reconciles a WorkloadPolicy object.
type WorkloadPolicyReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *WorkloadPolicyReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	policy := &v1alpha1.WorkloadPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get WorkloadPolicy '%s/%s': %w", req.Namespace, req.Name, err)
	}

	// Check if the policy is being deleted
	if !policy.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, policy)
	}

	return ctrl.Result{}, nil
}

func (r *WorkloadPolicyReconciler) handleDeletion(
	ctx context.Context,
	policy *v1alpha1.WorkloadPolicy,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(policy, v1alpha1.WorkloadPolicyFinalizer) {
		// Check if any pods are using this policy
		// Note, this uses a PartialObjectMetadataList because the Pod cache
		// is configured to only store metadata
		podList := &metav1.PartialObjectMetadataList{}
		podList.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "PodList",
		})

		var err error
		err = r.List(ctx, podList,
			client.InNamespace(policy.Namespace),
			client.MatchingLabels{v1alpha1.PolicyLabelKey: policy.Name},
		)
		if err != nil {
			logger.Error(err, "Failed to list pods using policy")
			return ctrl.Result{}, fmt.Errorf("failed to list pods using policy: %w", err)
		}

		if len(podList.Items) > 0 {
			logger.Info("Cannot remove finalizer: policy still in use by pods",
				"policy", policy.Name,
				"podCount", len(podList.Items))
			// Requeue to check again later
			return ctrl.Result{RequeueAfter: PolicyDeletionRequeueDelay}, nil
		}

		// No pods using this policy, safe to remove finalizer
		original := policy.DeepCopy()
		controllerutil.RemoveFinalizer(policy, v1alpha1.WorkloadPolicyFinalizer)
		if err = r.Patch(ctx, policy, client.MergeFrom(original)); err != nil {
			return ctrl.Result{}, fmt.Errorf(
				"failed to remove finalizer from WorkloadPolicy '%s/%s': %w",
				policy.Namespace, policy.Name, err,
			)
		}
		logger.Info("Removed finalizer from WorkloadPolicy", "policy", policy.Name)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.WorkloadPolicy{}).
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(r.findPoliciesForPod),
			builder.OnlyMetadata,
			builder.WithPredicates(predicate.LabelChangedPredicate{}),
		).
		Named("workloadpolicy").
		Complete(r)
	if err != nil {
		return fmt.Errorf("unable to set up WorkloadPolicy controller: %w", err)
	}
	return nil
}

// findPoliciesForPod maps a Pod to the WorkloadPolicy(s) it references.
func (r *WorkloadPolicyReconciler) findPoliciesForPod(_ context.Context, pod client.Object) []ctrl.Request {
	policyName, ok := pod.GetLabels()[v1alpha1.PolicyLabelKey]
	if !ok {
		return nil
	}

	return []ctrl.Request{
		{
			NamespacedName: client.ObjectKey{
				Name:      policyName,
				Namespace: pod.GetNamespace(),
			},
		},
	}
}
