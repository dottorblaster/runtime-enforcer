|              |                                          |
| :----------- | :--------------------------------------- |
| Feature Name | Kubernetes-Native Violation Reporting    |
| Start Date   | 2026-02-06                               |
| Category     | Observability                            |
| RFC PR       | [fill this in after opening PR]          |
| State        | **ACCEPTED**                             |

# Summary

[summary]: #summary

Add violation reporting paths so that policy violations are visible through
standard Kubernetes primitives (`kubectl describe`, `kubectl get`) without
requiring external observability infrastructure. Each agent buffers violation
records and patches WorkloadPolicy status with the most recent 100 entries.
Optionally, agents emit OTEL events (log records with `event_name` set) to a
standalone OTEL collector Deployment.

# Motivation

[motivation]: #motivation

Today, policy violations (unauthorized process executions detected by eBPF)
are only emitted as OpenTelemetry spans to an external collector. Viewing them
requires separate infrastructure such as Jaeger or Tempo, which is a poor
experience for Kubernetes-native workflows where users expect `kubectl` to be
the primary interface.

By surfacing violations as status records:

- Users see recent violation detail via `kubectl describe workloadpolicy`.
- Users get an at-a-glance view of recent violations via the status subresource.
- No external observability stack is required for basic violation visibility.

## Examples / User Stories

[examples]: #examples

**As a cluster operator**, I want to run `kubectl describe workloadpolicy my-policy`
and see recent violations with details (executable, pod, container, node) so I
can quickly triage unauthorized process executions.

**As a platform engineer**, I want `kubectl get workloadpolicy -o yaml` to show
recent violation records so I can identify noisy policies at a glance.

**As a security team member**, I still want violations flowing to existing o11y
setups via the existing OTEL span pipeline, unaffected by this change. I also
want structured OTEL events for integration with log-based alerting.

# Detailed design

[design]: #detailed-design

## Architecture

```
Agent (per node):
  eBPF -> EventScraper -> OTEL Span  ──┐
                       -> OTEL Event ───┼──→ Standalone OTEL Collector Deployment
                       -> WorkloadPolicy Status.Violations (batched flush from agent)

OTEL Collector Deployment (per cluster):
  ├─ logs pipeline   → count connector + debug exporter
  │                       ↓
  │                   metrics pipeline → deltatocumulative → prometheus exporter (:9090)
  └─ traces pipeline → otlp exporter → external collector (telemetry.custom.endpoint)
```

All telemetry (traces and violation events) is sent to a standalone OTEL
collector Deployment at `<release>-otel-collector.<namespace>.svc.cluster.local:4317`.
The collector handles routing: violation events are counted into Prometheus
metrics, and traces are forwarded to an external collector if configured.

All violation handling happens on the agent. The operator is not involved in
violation reporting.

## Agent side

### ViolationReporter (`internal/agent/violation_reporter.go`)

A component that implements `manager.Runnable`. It receives violation info
in-process from the EventScraper (no gRPC/OTLP needed) and:

1. Appends a `ViolationRecord` to an in-memory buffer keyed by policy
   namespaced name.
2. On a configurable tick interval (default 10s), swaps the buffer and for
   each entry patches `WorkloadPolicy.Status.Violations` using a merge patch.
3. When patching, fetches the current WP status, merges buffered records with
   existing violations, sorts by timestamp (newest first), and truncates to
   the most recent 100 entries (`MaxViolationRecords`).

Using `Status().Patch()` with merge patch avoids conflicts with the existing
`WorkloadPolicyStatusSync` which does full `Status().Update()` calls.

### OTEL event pipeline (`internal/events/events.go`)

The `Init` function creates an `sdklog.LoggerProvider` with an `otlploggrpc`
exporter. The endpoint is configurable to point at the standalone OTEL
collector or a third-party collector.

Violation records are emitted as OTEL events by calling
`Record.SetEventName("policy_violation")` before `Emit()`. This marks them
as structured events on the OTLP wire protocol (available in `otel/log`
v0.16.0+).

### EventScraper changes

The `EventScraper` gains an optional `ViolationReporter` via a functional
option (`WithViolationReporter`). In the monitoring channel handler, after the
existing `span.End()` and `emitViolationEvent()`, a `reportViolation()` call
sends violation info to the ViolationReporter for status patching.

The existing `WithViolationLogger` option for OTEL event emission is preserved
and now targets the standalone collector.

### Agent flags

- `--violation-otlp-endpoint`: gRPC endpoint for OTEL event reporting
  (standalone collector or third-party collector, empty = disabled).
- `--violation-flush-interval`: how often to flush violation records to
  WorkloadPolicy status (default 10s).
- `--node-name`: defaults to `NODE_NAME` env var from Downward API.

## CRD changes

A `ViolationRecord` struct captures individual violation details, and a
`ViolationStatus` struct holds the most recent records:

```go
const MaxViolationRecords = 100

type ViolationRecord struct {
    Timestamp      metav1.Time `json:"timestamp"`
    PodName        string      `json:"podName"`
    ContainerName  string      `json:"containerName"`
    ExecutablePath string      `json:"executablePath"`
    NodeName       string      `json:"nodeName"`
    Action         string      `json:"action"`
}

type ViolationStatus struct {
    Violations []ViolationRecord `json:"violations,omitempty"`
}
```

The existing status sync (`processWorkloadPolicy`) preserves the `Violations`
field after recomputing node-level status, so periodic syncs don't wipe
violation records.

## RBAC

The agent role needs:
- `get` and `patch` on `workloadpolicies/status` (for violation record
  patching).

The agent does **not** need permissions to create Kubernetes Events.

# OTEL Collector Deployment

## Overview

An opinionated OTEL collector runs as a standalone Deployment (one replica per
cluster), enabled by default via `agent.violations.collector.enabled`. Agents
send all telemetry (violation events and traces) to the collector Service at
`<release>-otel-collector.<namespace>.svc.cluster.local:4317`.

A ClusterIP Service exposes:
- Port 4317 (OTLP gRPC) for receiving telemetry from agents
- Port 9090 (Prometheus) for metrics scraping

## Violation metrics

The collector uses the OTEL Collector `count` connector to derive a Prometheus
counter from violation event records:

```
runtime_enforcer_violations_total{policy_name, k8s_namespace_name, action, node_name}
```

The `deltatocumulative` processor converts the delta counters from the
`count` connector into cumulative counters suitable for Prometheus scraping.
Metrics are exposed on port 9090 via the `prometheus` exporter. The logs
pipeline also includes a `debug` exporter so that violation event records are
visible in the collector's stdout.

## Trace forwarding

When the collector is enabled, tracing is automatically enabled on the agent
(`--enable-tracing`). The agent sends all OTEL spans to the collector.

When `telemetry.custom.endpoint` is configured, the collector forwards traces
to the external collector via the OTLP exporter. When no external endpoint is
set, traces go to the `debug` exporter (stdout).

## Disabling the collector

Users who already have their own OTEL collector can set
`agent.violations.collector.enabled=false` and configure
`agent.violations.otlpEndpoint` and `telemetry.custom.endpoint` to point
directly at their collector. In this mode, `telemetry.tracing=true` must be
set explicitly, and no collector Deployment is created.

## Image

The collector uses `otel/opentelemetry-collector-contrib` because it requires
the `prometheus` exporter, `count` connector, and `deltatocumulative`
processor which are not available in the core distribution.

# Drawbacks

[drawbacks]: #drawbacks

- **Wider agent RBAC**: agents need permissions to patch WorkloadPolicy status,
  whereas previously they were read-only on the K8s API. This is the trade-off
  for a simpler architecture without operator-side violation processing.
- **Status patch conflicts**: while merge patch targets only the `violations`
  field, rapid concurrent patches from many agents could still cause transient
  conflicts. Some re-queue logic can handle this, but it adds some latency.
- **Status size**: storing up to 100 violation records in status increases the
  WP object size. The `MaxViolationRecords` cap keeps this bounded, but high
  violation rates will cause rapid turnover of records.

# Alternatives

[alternatives]: #alternatives

- **Route violations through the operator via OTLP**: the original design.
  Keeps agents read-only but adds a gRPC hop, requires the operator to run an
  OTLP receiver, and creates a single point of failure/bottleneck for
  violation reporting across all nodes.
- **Use Kubernetes Events for violations**: provides `kubectl describe`
  visibility and built-in dedup/TTL, but Events are ephemeral (default 1h
  TTL), not queryable via the status subresource, and add RBAC surface for
  event creation. Storing records in status provides a more durable and
  structured view.
- **Use a custom CRD for violations**: we explored two variants of this
  approach. The first was an atomic CRD where each violation produces its own
  resource (one CR per violation event). The second was a fatter, per-policy
  CRD that accumulates multiple violation records in a single resource (similar
  to what we do in status, but in a dedicated object). Both options offer
  cleaner separation of concerns, but they add significant overhead in terms of
  code: additional CRD definitions, controllers, RBAC rules, garbage
  collection logic, and generated client boilerplate. The current approach of
  storing the last 100 records directly in WorkloadPolicy status is simpler,
  covers all current use cases, and avoids the object sprawl and management
  complexity that a dedicated CRD would introduce. If future requirements
  demand longer retention or cross-policy querying, a dedicated CRD can be
  revisited.
- **Use the existing gRPC status sync channel**: avoids a new gRPC server, but
  conflates policy deployment status with runtime violations and would
  complicate the status sync protocol.

# Unresolved questions

[unresolved]: #unresolved-questions

- Should the `ViolationStatus` include per-node or per-container breakdowns,
  or is the flat list of the last 100 records sufficient for the initial version?
- Should the flush interval be configurable per-policy, or is a global default
  sufficient?
- Should the OTEL collector Deployment be scaled beyond 1 replica for HA, or
  is single-replica acceptable for the initial version?
