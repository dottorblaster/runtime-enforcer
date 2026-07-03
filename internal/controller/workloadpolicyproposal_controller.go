package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventhandler/proposalutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WorkloadPolicyProposalReconciler reconciles a WorkloadPolicyProposal object.
type WorkloadPolicyProposalReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch;create;patch

func (r *WorkloadPolicyProposalReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("workloadpolicyproposal", "req", req)

	var policyProposal securityv1alpha1.WorkloadPolicyProposal
	var err error

	if err = r.Get(ctx, req.NamespacedName, &policyProposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if policyProposal.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	// After a proposal is promoted and deleted, an agent can recreate a WorkloadPolicyProposal
	// at the same time. If a WorkloadPolicy already exists with promoted-from=<proposalName>,
	// treat the proposal as leftover and delete it. This is eventually reconciled on the controller-runtime
	// resync (SyncPeriod, 10 hours by default) if both the proposal and the policy are still in the cluster.
	var alreadyPromoted bool
	alreadyPromoted, err = proposalutils.HasProposalBeenPromoted(
		ctx, r.Client,
		policyProposal.Namespace,
		policyProposal.Name,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to check promoted WorkloadPolicy: %w", err)
	}
	if alreadyPromoted {
		log.Info("Deleting WorkloadPolicyProposal; promoted WorkloadPolicy already exists",
			"proposal", policyProposal.Name)
		if err = r.Delete(ctx, &policyProposal); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, nil
	}

	if policyProposal.GetLabels()[securityv1alpha1.ApprovalLabelKey] != "true" {
		return ctrl.Result{}, nil
	}

	policy := securityv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyProposal.ObjectMeta.Name,
			Namespace: policyProposal.ObjectMeta.Namespace,
			Labels: map[string]string{
				securityv1alpha1.PromotedFromLabelKey: policyProposal.Name,
			},
		},
		Spec: policyProposal.Spec.IntoWorkloadPolicySpec(),
	}

	if err = r.Create(ctx, &policy); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Info("WorkloadPolicy already exists, skipping creation", "policy", policy.NamespacedName())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to create WorkloadPolicy: %w", err)
	}

	// Once we successfully promote the proposal into a policy, we no longer
	// need the proposal to remain in the cluster.
	if err = r.Delete(ctx, &policyProposal); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkloadPolicyProposalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.WorkloadPolicyProposal{}).
		Named("workloadpolicyproposal").
		Complete(r)
}
