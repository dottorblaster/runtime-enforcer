package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"
	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ViolationInfo contains the details of a single policy violation.
type ViolationInfo struct {
	PolicyName    string
	Namespace     string
	PodName       string
	ContainerName string
	ExePath       string
	NodeName      string
	Action        string
}

// ViolationReporter implements manager.Runnable. It buffers violation records
// and periodically flushes them into WorkloadPolicy.Status.Violations,
// keeping only the most recent MaxViolationRecords entries.
type ViolationReporter struct {
	client        client.Client
	logger        logr.Logger
	flushInterval time.Duration

	mu      sync.Mutex
	pending map[types.NamespacedName][]securityv1alpha1.ViolationRecord
}

// ViolationReporterConfig holds configuration for the ViolationReporter.
type ViolationReporterConfig struct {
	FlushInterval time.Duration
}

// NewViolationReporter creates a new ViolationReporter.
func NewViolationReporter(
	c client.Client,
	logger logr.Logger,
	cfg ViolationReporterConfig,
) *ViolationReporter {
	return &ViolationReporter{
		client:        c,
		logger:        logger.WithName("violation-reporter"),
		flushInterval: cfg.FlushInterval,
		pending:       make(map[types.NamespacedName][]securityv1alpha1.ViolationRecord),
	}
}

// Report records a violation by appending a ViolationRecord to the buffer
// for the given policy.
func (vr *ViolationReporter) Report(_ context.Context, vi ViolationInfo) {
	if vi.PolicyName == "" || vi.Namespace == "" {
		vr.logger.V(1).Info("skipping violation with missing policy or namespace")
		return
	}

	nn := types.NamespacedName{Namespace: vi.Namespace, Name: vi.PolicyName}
	rec := securityv1alpha1.ViolationRecord{
		Timestamp:      metav1.Now(),
		PodName:        vi.PodName,
		ContainerName:  vi.ContainerName,
		ExecutablePath: vi.ExePath,
		NodeName:       vi.NodeName,
		Action:         vi.Action,
	}

	vr.mu.Lock()
	vr.pending[nn] = append(vr.pending[nn], rec)
	vr.mu.Unlock()
}

// Start implements manager.Runnable. It runs the periodic status flusher
// and blocks until the context is cancelled.
func (vr *ViolationReporter) Start(ctx context.Context) error {
	vr.logger.Info("starting violation reporter", "flushInterval", vr.flushInterval)

	ticker := time.NewTicker(vr.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			vr.flush(ctx)
		}
	}
}

func (vr *ViolationReporter) flush(ctx context.Context) {
	vr.mu.Lock()
	if len(vr.pending) == 0 {
		vr.mu.Unlock()
		return
	}
	batch := vr.pending
	vr.pending = make(map[types.NamespacedName][]securityv1alpha1.ViolationRecord)
	vr.mu.Unlock()

	for nn, records := range batch {
		if err := vr.patchViolationStatus(ctx, nn, records); err != nil {
			vr.logger.Error(err, "failed to patch violation status", "policy", nn)
			// Re-queue the records so they aren't lost.
			vr.mu.Lock()
			vr.pending[nn] = append(vr.pending[nn], records...)
			vr.mu.Unlock()
		}
	}
}

func (vr *ViolationReporter) patchViolationStatus(
	ctx context.Context,
	nn types.NamespacedName,
	newRecords []securityv1alpha1.ViolationRecord,
) error {
	var wp securityv1alpha1.WorkloadPolicy
	if err := vr.client.Get(ctx, nn, &wp); err != nil {
		return fmt.Errorf("get WorkloadPolicy: %w", err)
	}

	// Merge existing violations with new records.
	var existing []securityv1alpha1.ViolationRecord
	if wp.Status.Violations != nil {
		existing = wp.Status.Violations.Violations
	}
	merged := append(existing, newRecords...)

	// Sort by timestamp descending (newest first) and keep only the last MaxViolationRecords.
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Timestamp.Time.After(merged[j].Timestamp.Time)
	})
	if len(merged) > securityv1alpha1.MaxViolationRecords {
		merged = merged[:securityv1alpha1.MaxViolationRecords]
	}

	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"violations": map[string]interface{}{
				"violations": merged,
			},
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

	return vr.client.Status().Patch(ctx, &wp, client.RawPatch(types.MergePatchType, patchBytes))
}
