package controller

import (
	"context"
	"fmt"
	"net/http"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type ProposalWebhook struct {
	Client client.Client
}

var _ apierrors.APIStatus = (*ProposalValidatorError)(nil)

type ProposalValidatorError struct {
	status metav1.Status
}

func (e *ProposalValidatorError) Error() string {
	return fmt.Sprintf("failed to validate proposal: %s", e.status.Message)
}

func (e *ProposalValidatorError) Status() metav1.Status {
	return e.status
}

// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get

func (p *ProposalWebhook) updateResource(
	ctx context.Context,
	proposal *securityv1alpha1.WorkloadPolicyProposal,
) error {
	var res schema.GroupVersionKind
	ownerRef := proposal.OwnerReferences[0]

	// the proposal contains a partial owner reference so that here we can understand which resource to query.
	switch ownerRef.Kind {
	case "Deployment":
		res = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: ownerRef.Kind}
	case "DaemonSet":
		res = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: ownerRef.Kind}
	case "StatefulSet":
		res = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: ownerRef.Kind}
	case "ReplicaSet":
		res = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: ownerRef.Kind}
	case "Job":
		res = schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: ownerRef.Kind}
	case "CronJob":
		res = schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: ownerRef.Kind}
	default:
		return &ProposalValidatorError{
			status: metav1.Status{
				Message: fmt.Sprintf("invalid proposal: not supported resource type: %s", ownerRef.Kind),
				Code:    http.StatusUnprocessableEntity,
				Reason:  metav1.StatusReasonInvalid,
			},
		}
	}

	// unstructured does not trigger cache mechanism in controller-runtime's client.
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(res)
	err := p.Client.Get(ctx, types.NamespacedName{
		Namespace: proposal.Namespace,
		Name:      ownerRef.Name,
	}, obj)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return &ProposalValidatorError{
				status: metav1.Status{
					Message: fmt.Sprintf(
						"the owner reference %s %s/%s is not found",
						ownerRef.Kind,
						proposal.Namespace,
						ownerRef.Name,
					),
					Code:   http.StatusGone,
					Reason: metav1.StatusReasonGone,
				},
			}
		}

		return fmt.Errorf("failed to get %s %s %s: %w", ownerRef.Kind, proposal.Namespace, ownerRef.Name, err)
	}

	proposal.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion:         res.GroupVersion().String(),
			Kind:               ownerRef.Kind,
			Name:               ownerRef.Name,
			UID:                obj.GetUID(),
			Controller:         new(true),
			BlockOwnerDeletion: new(true),
		},
	}

	return nil
}

// Default filling ownerReferences and selectors fields based on the high level resource defined
// in its ownerReferences, where caller still need to specify its kind and name.
func (p *ProposalWebhook) Default(ctx context.Context, proposal *securityv1alpha1.WorkloadPolicyProposal) error {
	logger := log.FromContext(ctx)
	logger.Info("mutating resource")

	if len(proposal.OwnerReferences) != 1 {
		return &ProposalValidatorError{
			status: metav1.Status{
				Message: "invalid proposal: only one owner reference is expected",
				Code:    http.StatusUnprocessableEntity,
				Reason:  metav1.StatusReasonInvalid,
			},
		}
	}

	if proposal.OwnerReferences[0].Kind == "" {
		return &ProposalValidatorError{
			status: metav1.Status{
				Message: "invalid proposal: kind is not specified in the owner reference",
				Code:    http.StatusUnprocessableEntity,
				Reason:  metav1.StatusReasonInvalid,
			},
		}
	}

	if proposal.OwnerReferences[0].Name == "" {
		return &ProposalValidatorError{
			status: metav1.Status{
				Message: "invalid proposal: name is not specified in the owner reference",
				Code:    http.StatusUnprocessableEntity,
				Reason:  metav1.StatusReasonInvalid,
			},
		}
	}

	if proposal.OwnerReferences[0].UID != "" {
		// The default has been provided.
		return nil
	}

	return p.updateResource(ctx, proposal)
}
