package controller

import (
	"context"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type PolicyWebhook struct{}

// Default adds a finalizer to WorkloadPolicy on CREATE and UPDATE events.
func (w *PolicyWebhook) Default(ctx context.Context, policy *v1alpha1.WorkloadPolicy) error {
	logger := log.FromContext(ctx)

	// Check if the policy is being deleted
	if !policy.DeletionTimestamp.IsZero() {
		// No need to default a deleting object
		return nil
	}

	// Add finalizer to ensure a policy cannot be deleted while in use by pods
	// This handles both CREATE events and UPDATE events (e.g., when a proposal is promoted to a policy)
	if updated := controllerutil.AddFinalizer(policy, v1alpha1.WorkloadPolicyFinalizer); updated {
		logger.Info("added finalizer to WorkloadPolicy", "name", policy.GetName())
	}

	return nil
}
