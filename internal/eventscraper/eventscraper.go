package eventscraper

import (
	"context"
	"log/slog"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"github.com/rancher-sandbox/runtime-enforcer/internal/violationbuf"
	otellog "go.opentelemetry.io/otel/log"
)

type EventScraper struct {
	learningChannel     <-chan bpf.ProcessEvent
	monitoringChannel   <-chan bpf.ProcessEvent
	logger              *slog.Logger
	resolver            *resolver.Resolver
	learningEnqueueFunc func(evt KubeProcessInfo)
	violationLogger     otellog.Logger
	violationBuffer     *violationbuf.Buffer
	nodeName            string
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

type Option func(*EventScraper)

// WithViolationLogger sets an OTEL logger for emitting violation event records.
func WithViolationLogger(l otellog.Logger, nodeName string) Option {
	return func(es *EventScraper) {
		es.violationLogger = l
		es.nodeName = nodeName
	}
}

// WithViolationBuffer sets the ViolationBuffer for buffering violation
// records in-memory for later scraping by the controller.
func WithViolationBuffer(buf *violationbuf.Buffer, nodeName string) Option {
	return func(es *EventScraper) {
		es.violationBuffer = buf
		es.nodeName = nodeName
	}
}

func NewEventScraper(
	learningChannel <-chan bpf.ProcessEvent,
	monitoringChannel <-chan bpf.ProcessEvent,
	logger *slog.Logger,
	resolver *resolver.Resolver,
	learningEnqueueFunc func(evt KubeProcessInfo),
	opts ...Option,
) *EventScraper {
	es := &EventScraper{
		learningChannel:     learningChannel,
		monitoringChannel:   monitoringChannel,
		logger:              logger,
		resolver:            resolver,
		learningEnqueueFunc: learningEnqueueFunc,
	}
	for _, option := range opts {
		option(es)
	}
	return es
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

			action := event.Mode

			policyName := kubeInfo.PolicyName
			if policyName == "" {
				es.logger.ErrorContext(ctx, "missing policy label for",
					"pod", kubeInfo.PodName,
					"namespace", kubeInfo.Namespace)
			}

			es.emitViolationEvent(ctx, kubeInfo, action)
			es.reportViolation(kubeInfo, action)
		}
	}
}

func (es *EventScraper) emitViolationEvent(ctx context.Context, info *KubeProcessInfo, action string) {
	if es.violationLogger == nil {
		return
	}

	var rec otellog.Record
	rec.SetEventName("policy_violation")
	rec.SetSeverity(otellog.SeverityWarn)
	rec.SetBody(otellog.StringValue("policy_violation"))
	rec.SetTimestamp(time.Now())
	rec.AddAttributes(
		otellog.String("policy.name", info.PolicyName),
		otellog.String("k8s.namespace.name", info.Namespace),
		otellog.String("k8s.pod.name", info.PodName),
		otellog.String("container.name", info.ContainerName),
		otellog.String("proc.exepath", info.ExecutablePath),
		otellog.String("node.name", es.nodeName),
		otellog.String("action", action),
	)

	es.violationLogger.Emit(ctx, rec)
}

func (es *EventScraper) reportViolation(info *KubeProcessInfo, action string) {
	es.violationBuffer.Record(violationbuf.ViolationInfo{
		PolicyName:    info.PolicyName,
		Namespace:     info.Namespace,
		PodName:       info.PodName,
		ContainerName: info.ContainerName,
		ExePath:       info.ExecutablePath,
		NodeName:      es.nodeName,
		Action:        action,
	})
}
