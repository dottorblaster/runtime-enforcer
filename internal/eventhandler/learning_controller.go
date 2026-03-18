package eventhandler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventscraper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// DefaultEventChannelBufferSize defines the channel buffer size used to
// deliver events to learning_controller.
// This is a arbitrary number right now and can be fine-tuned or made configurable in the future.
// On a simple kind cluster we saw more than 4200 process exec during the initial process cache dump, so this seems a reasonable default for now.
const DefaultEventChannelBufferSize = 4096

// GetWorkloadPolicyProposalName returns the name of WorkloadPolicyProposal
// based on a high level resource and its name.
func GetWorkloadPolicyProposalName(kind string, resourceName string) (string, error) {
	var shortname string
	switch kind {
	case "Deployment":
		shortname = "deploy"
	case "ReplicaSet":
		shortname = "rs"
	case "DaemonSet":
		shortname = "ds"
	case "CronJob":
		shortname = "cronjob"
	case "Job":
		shortname = "job"
	case "StatefulSet":
		shortname = "sts"
	default:
		return "", fmt.Errorf("unknown kind: %s", kind)
	}
	ret := shortname + "-" + resourceName

	// The max name length in k8s
	if len(ret) > validation.DNS1123SubdomainMaxLength {
		return "", fmt.Errorf("the name %s exceeds the maximum name length", ret)
	}

	return shortname + "-" + resourceName, nil
}

type LearningReconciler struct {
	client.Client

	Scheme            *runtime.Scheme
	eventChan         chan event.TypedGenericEvent[eventscraper.KubeProcessInfo]
	tracer            trace.Tracer
	namespaceSelector labels.Selector
	// OwnerRefEnricher can be overridden during testing
	OwnerRefEnricher func(wp *securityv1alpha1.WorkloadPolicyProposal, workloadKind string, workload string)
}

func NewLearningReconciler(
	client client.Client,
	selector labels.Selector,
) *LearningReconciler {
	return &LearningReconciler{
		Client: client,
		eventChan: make(
			chan event.TypedGenericEvent[eventscraper.KubeProcessInfo],
			DefaultEventChannelBufferSize,
		),
		tracer: otel.Tracer(
			"runtime-enforcer-learner",
		),
		namespaceSelector: selector,
		OwnerRefEnricher: func(wp *securityv1alpha1.WorkloadPolicyProposal, workloadKind string, workload string) {
			wp.OwnerReferences = []metav1.OwnerReference{
				{
					Kind: workloadKind,
					Name: workload,
				},
			}
		},
	}
}

// handleAdmissionError deals with the errors returned by our mutating webhook.
func (r *LearningReconciler) handleAdmissionError(logger logr.Logger, err error) error {
	var apistatus apierrors.APIStatus
	if !errors.As(err, &apistatus) {
		return err
	}

	switch apistatus.Status().Code {
	case http.StatusUnprocessableEntity:
		// The item is rejected by the webhook.
		// This means something seriously wrong with the request and we should stop retrying.
		logger.Error(
			err,
			"Failed to update WorkloadPolicyProposal because the proposal is rejected by the webhook",
		)
		return nil
	case http.StatusGone:
		// This happens when the top-level workload is deleted.
		// We don't need to retry anymore.
		logger.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
			"Failed to update WorkloadPolicyProposal because the owner workload has been deleted",
		)
		return nil
	case http.StatusForbidden:
		// This happens when the admission webhook rejects the request normally without specifying a special error code.
		// This means transient errors that we should retry.
		return err
	case http.StatusInternalServerError:
		// This happens when the admission webhook is down. We should retry.
		return err
	default:
		return fmt.Errorf(
			"error code %d received when running CreateOrUpdate: %w",
			apistatus.Status().Code,
			err,
		)
	}
}

// kubebuilder annotations for accessing policy proposals and namespaces.
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals,verbs=create;get;list;watch;update;patch

// Reconcile receives learning events and creates/updates WorkloadPolicyProposal resources accordingly.
func (r *LearningReconciler) Reconcile(
	ctx context.Context,
	req eventscraper.KubeProcessInfo,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues(
		"namespace", req.Namespace,
		"workload", req.Workload,
		"workload_kind", req.WorkloadKind,
		"exe", req.ExecutablePath,
	)

	logger.V(3).Info("Reconciling", "req", req) //nolint:mnd // 3 is the verbosity level for detailed debug info

	var err error
	var proposalName string

	if req.WorkloadKind == "Pod" {
		// We don't support learning on standalone pods

		logger.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
			"Ignoring learning event",
		)

		return ctrl.Result{}, nil
	}

	if r.namespaceSelector != nil {
		var ns corev1.Namespace
		if err = r.Client.Get(ctx, types.NamespacedName{Name: req.Namespace}, &ns); err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
					"Namespace not found while evaluating learning namespace selector",
				)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("failed to get namespace %s: %w", req.Namespace, err)
		}
		if !r.namespaceSelector.Matches(labels.Set(ns.GetLabels())) {
			logger.V(1).
				Info("Namespace does not match learning namespace selector; skipping event", "namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
	}

	proposalName, err = GetWorkloadPolicyProposalName(req.WorkloadKind, req.Workload)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get proposal name: %w", err)
	}

	policyProposal := &securityv1alpha1.WorkloadPolicyProposal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proposalName,
			Namespace: req.Namespace,
		},
	}

	var result controllerutil.OperationResult

	if result, err = controllerutil.CreateOrUpdate(ctx, r.Client, policyProposal, func() error {
		// We don't learn any new process if the policy proposal was promoted
		// to an actual policy
		labels := policyProposal.GetLabels()
		if labels[securityv1alpha1.ApprovalLabelKey] == "true" {
			return nil
		}

		if err = policyProposal.AddProcess(req.ContainerName, req.ExecutablePath); err != nil {
			return fmt.Errorf("failed to add process to policy proposal: %w", err)
		}

		// If the owner reference is already there we do nothing.
		// We should always have the owner reference populated unless we are creating the resource for the first time.
		if len(policyProposal.OwnerReferences) != 0 {
			return nil
		}

		// if we don't populate a partial owner reference here the webhook won't be able to populate the owner reference because it doesn't know who is the owner.
		r.OwnerRefEnricher(policyProposal, req.WorkloadKind, req.Workload)
		return nil
	}); err != nil {
		return ctrl.Result{}, r.handleAdmissionError(logger, err)
	}

	// Emit trace when a new process is learned.
	if result != controllerutil.OperationResultNone {
		var span trace.Span
		now := time.Now()
		_, span = r.tracer.Start(ctx, "process learned")
		span.SetAttributes(
			attribute.String("evt.time", now.Format(time.RFC3339)),
			attribute.Int64("evt.rawtime", now.UnixNano()),
			attribute.String("k8s.ns.name", req.Namespace),
			attribute.String("k8s.workload.kind", req.WorkloadKind),
			attribute.String("k8s.workload.name", req.Workload),
			attribute.String("container.name", req.ContainerName),
			attribute.String("proc.exepath", req.ExecutablePath),
		)
		span.End()
	}

	return ctrl.Result{}, nil
}

func (r *LearningReconciler) EnqueueEvent(evt eventscraper.KubeProcessInfo) {
	r.eventChan <- event.TypedGenericEvent[eventscraper.KubeProcessInfo]{Object: evt}
}

// ProcessEventHandler implements handler.TypedEventHandler[eventscraper.KubeProcessInfo, eventscraper.KubeProcessInfo].
type ProcessEventHandler struct {
}

func (e ProcessEventHandler) Create(
	_ context.Context,
	_ event.TypedCreateEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {

}

func (e ProcessEventHandler) Update(
	_ context.Context,
	_ event.TypedUpdateEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {

}

func (e ProcessEventHandler) Delete(
	_ context.Context,
	_ event.TypedDeleteEvent[eventscraper.KubeProcessInfo],
	_ workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {

}

func (e ProcessEventHandler) Generic(
	_ context.Context,
	evt event.TypedGenericEvent[eventscraper.KubeProcessInfo],
	q workqueue.TypedRateLimitingInterface[eventscraper.KubeProcessInfo],
) {
	q.AddRateLimited(evt.Object)
}

// SetupWithManager sets up the controller with the Manager.
func (r *LearningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return builder.TypedControllerManagedBy[eventscraper.KubeProcessInfo](mgr).
		Named("learningEvent").
		WatchesRawSource(
			source.TypedChannel(
				r.eventChan,
				&ProcessEventHandler{},
			),
		).
		Complete(r)
}
