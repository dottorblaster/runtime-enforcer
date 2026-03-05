package eventscraper

import (
	"context"
	"log/slog"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type EventScraper struct {
	learningChannel     <-chan bpf.ProcessEvent
	monitoringChannel   <-chan bpf.ProcessEvent
	logger              *slog.Logger
	resolver            *resolver.Resolver
	learningEnqueueFunc func(evt KubeProcessInfo)
	tracer              trace.Tracer
}

type KubeProcessInfo struct {
	Namespace      string `json:"namespace"`
	Workload       string `json:"workload"`
	WorkloadKind   string `json:"workloadKind"`
	ContainerName  string `json:"containerName"`
	ExecutablePath string `json:"executablePath"`
	PodName        string `json:"podName"`
	ContainerID    string `json:"containerID"`
	PolicyName     string `json:"policyName,omitempty"`
}

func NewEventScraper(
	learningChannel <-chan bpf.ProcessEvent,
	monitoringChannel <-chan bpf.ProcessEvent,
	logger *slog.Logger,
	resolver *resolver.Resolver,
	learningEnqueueFunc func(evt KubeProcessInfo),
) *EventScraper {
	return &EventScraper{
		learningChannel:     learningChannel,
		monitoringChannel:   monitoringChannel,
		logger:              logger,
		resolver:            resolver,
		learningEnqueueFunc: learningEnqueueFunc,
		tracer:              otel.Tracer("event-scraper"),
	}
}

func (es *EventScraper) getKubeProcessInfo(event *bpf.ProcessEvent) *KubeProcessInfo {
	// trackerID is the ID of the container cgroup where the process is running.
	// NRI will populate cgroup tracker map before we will start to generate learning/monitor events from ebpf.
	containerView, err := es.resolver.GetContainerView(event.CgTrackerID)
	if err != nil {
		es.logger.Error("failed to get pod info",
			"cgTrackerID", event.CgTrackerID,
			"exe", event.ExePath,
			"error", err)
		return nil
	}

	podMeta := containerView.PodMeta
	containerMeta := containerView.Meta
	policyName := ""
	if podMeta.Labels != nil {
		policyName = podMeta.Labels[v1alpha1.PolicyLabelKey]
	}

	return &KubeProcessInfo{
		Namespace:      podMeta.Namespace,
		Workload:       podMeta.WorkloadName,
		WorkloadKind:   podMeta.WorkloadType,
		ContainerName:  containerMeta.Name,
		ExecutablePath: event.ExePath,
		PodName:        podMeta.Name,
		ContainerID:    containerMeta.ID,
		PolicyName:     policyName,
	}
}

// Start begins the event scraping process.
func (es *EventScraper) Start(ctx context.Context) error {
	defer func() {
		es.logger.InfoContext(ctx, "event scraper has stopped")
	}()

	for {
		select {
		case <-ctx.Done():
			// Handle context cancellation
			return nil
		case event := <-es.learningChannel:
			kubeInfo := es.getKubeProcessInfo(&event)
			if kubeInfo == nil {
				continue
			}
			es.learningEnqueueFunc(*kubeInfo)
		case event := <-es.monitoringChannel:
			kubeInfo := es.getKubeProcessInfo(&event)
			if kubeInfo == nil {
				continue
			}

			now := time.Now()
			var span trace.Span
			action := event.Mode

			policyName := kubeInfo.PolicyName
			if policyName == "" {
				es.logger.ErrorContext(ctx, "missing policy label for",
					"pod", kubeInfo.PodName,
					"namespace", kubeInfo.Namespace)
			}
			_, span = es.tracer.Start(ctx, action)
			span.SetAttributes(
				attribute.String("evt.time", now.Format(time.RFC3339)),
				attribute.Int64("evt.rawtime", now.UnixNano()),
				attribute.String("policy.name", policyName),
				attribute.String("k8s.ns.name", kubeInfo.Namespace),
				attribute.String("k8s.workload.name", kubeInfo.Workload),
				attribute.String("k8s.workload.kind", kubeInfo.WorkloadKind),
				attribute.String("k8s.pod.name", kubeInfo.PodName),
				attribute.String("container.full_id", kubeInfo.ContainerID),
				attribute.String("container.name", kubeInfo.ContainerName),
				attribute.String("proc.exepath", kubeInfo.ExecutablePath),
				attribute.String("action", action),
			)
			span.End()
		}
	}
}
