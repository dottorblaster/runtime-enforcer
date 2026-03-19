package eventhandler

import (
	"context"
	"fmt"
	"time"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventhandler/utils"
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

// kubebuilder annotations for accessing policy proposals and namespaces.
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicyproposals,verbs=create;get;list;watch;update;patch

// Reconcile receives learning events and creates/updates WorkloadPolicyProposal resources accordingly.
func (r *LearningReconciler) Reconcile(
	ctx context.Context,
	req eventscraper.KubeProcessInfo,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.V(3).Info("Reconciling", "req", req) //nolint:mnd // 3 is the verbosity level for detailed debug info

	var err error
	var proposalName string

	if req.WorkloadKind == "Pod" {
		// We don't support learning on standalone pods

		log.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
			"Ignoring learning event",
			"workload", req.Workload,
			"workload_kind", req.WorkloadKind,
			"exe", req.ExecutablePath,
		)

		return ctrl.Result{}, nil
	}

	if r.namespaceSelector != nil {
		var ns corev1.Namespace
		if err = r.Client.Get(ctx, types.NamespacedName{Name: req.Namespace}, &ns); err != nil {
			if apierrors.IsNotFound(err) {
				log.V(3).Info( //nolint:mnd // 3 is the verbosity level for detailed debug info
					"Namespace not found while evaluating learning namespace selector",
					"namespace", req.Namespace,
				)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("failed to get namespace %s: %w", req.Namespace, err)
		}
		if !r.namespaceSelector.Matches(labels.Set(ns.GetLabels())) {
			log.V(1).
				Info("Namespace does not match learning namespace selector; skipping event", "namespace", req.Namespace)
			return ctrl.Result{}, nil
		}
	}

	proposalName, err = utils.GetWorkloadPolicyProposalName(req.WorkloadKind, req.Workload)
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
		return ctrl.Result{}, fmt.Errorf("failed to run CreateOrUpdate: %w", err)
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
