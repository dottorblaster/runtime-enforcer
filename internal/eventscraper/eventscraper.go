package eventscraper

import (
	"context"
	"errors"
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
	// trackerID should be the ID of the cgroup of the container where the process is running
	cgIDLookup := event.CgTrackerID
	// this could happen if the resolver has not yet seen the pod or it was not able to scrape the container info
	if cgIDLookup == 0 {
		// most of the times the cgroupID should be identical to the trackerID if the process is not in a nested cgroup inside the container
		if event.CgroupID == 0 {
			es.logger.Warn("process event with empty cgroupID and cgIDTracker, skipping event")
			return nil
		}
		cgIDLookup = event.CgroupID
	}

	es.logger.Debug("process event with empty cgIDTracker, falling back to cgroupID", "cgID", event.CgroupID)
	info, err := es.resolver.GetKubeInfo(cgIDLookup)
	if err == nil {
		policyName := ""
		if info.Labels != nil {
			policyName = info.Labels[v1alpha1.PolicyLabelKey]
		}

		return &KubeProcessInfo{
			Namespace:      info.Namespace,
			Workload:       info.WorkloadName,
			WorkloadKind:   info.WorkloadType,
			ContainerName:  info.ContainerName,
			ExecutablePath: event.ExePath,
			PodName:        info.PodName,
			ContainerID:    info.ContainerID,
			PolicyName:     policyName,
		}
	}

	switch {
	case errors.Is(err, resolver.ErrMissingPodUID):
		// This could happen if the cgroup ID is not associated with any pod (is on the host), that's why we put it in debug
		// todo!: with the debug we could miss some actual miss in production
		es.logger.Debug("missing pod UID for process event",
			"msg", err.Error(),
			"exe", event.ExePath)
	case errors.Is(err, resolver.ErrMissingPodInfo):
		// This could happen if the pod was found but the info is not yet populated
		es.logger.Warn("missing pod info for process event",
			"msg", err.Error(),
			"exe", event.ExePath)
	default:
		// Some other error
		es.logger.Error("unknown error getting kube info for process event",
			"cgID", cgIDLookup,
			"exe", event.ExePath,
			"error", err)
	}

	return nil
}

// Start begins the event scraping process.
func (es *EventScraper) Start(ctx context.Context) error {
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
	if es.violationBuffer == nil {
		return
	}

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
