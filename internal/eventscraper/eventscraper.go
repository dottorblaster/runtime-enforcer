package eventscraper

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
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
		// todo!: with the debug we could miss some real miss in production but not sure we can ignore cgroup IDs on the host in some other way
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
// todo!: we should also send the initial state of the processes running on the system. We could use BPF iterators or /proc.
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
				// todo!: not sure we need this info for v1 (?)
				// attribute.Int64("proc.pid", int64(proc.GetPid().GetValue())),
				// attribute.String("proc.pexepath", proc.GetBinary()),
				attribute.String("proc.exepath", kubeInfo.ExecutablePath),
				attribute.String("action", action),
			)
			span.End()
		}
	}
}
