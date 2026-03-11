package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

func getOtelCollectorTest() types.Feature {
	return features.New("OTEL Collector Violation Metrics").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			workloadNamespace := envconf.RandomName("otel-namespace", 32)

			t.Log("creating test namespace")
			r := ctx.Value(key("client")).(*resources.Resources)

			namespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace}}
			err := r.Create(ctx, &namespace)
			require.NoError(t, err, "failed to create test namespace")

			return context.WithValue(ctx, key("namespace"), workloadNamespace)
		}).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("installing test Ubuntu deployment")
			r := ctx.Value(key("client")).(*resources.Resources)
			namespace := ctx.Value(key("namespace")).(string)

			err := decoder.ApplyWithManifestDir(
				ctx, r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.CreateOption{},
				decoder.MutateNamespace(namespace),
			)
			require.NoError(t, err, "failed to apply test data")

			err = wait.For(
				conditions.New(r).DeploymentAvailable("ubuntu-deployment", namespace),
				wait.WithTimeout(DefaultOperationTimeout),
			)
			require.NoError(t, err)

			ubuntuPodName, err := findPod(ctx, namespace, "ubuntu-deployment")
			require.NoError(t, err)
			require.NotEmpty(t, ubuntuPodName)

			return context.WithValue(ctx, key("targetPodName"), ubuntuPodName)
		}).
		Assess("required resources become available", IfRequiredResourcesAreCreated).
		Assess("OTEL collector deployment is ready",
			func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
				r := ctx.Value(key("client")).(*resources.Resources)

				t.Log("waiting for OTEL collector deployment to be available")
				err := wait.For(
					conditions.New(r).DeploymentAvailable(
						otelCollectorDeploymentName,
						runtimeEnforcerNamespace,
					),
					wait.WithTimeout(DefaultOperationTimeout),
				)
				require.NoError(t, err, "OTEL collector deployment should be available")

				return ctx
			}).
		Assess("violations produce Prometheus metrics on the collector",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				namespace := ctx.Value(key("namespace")).(string)
				expectedPodName := ctx.Value(key("targetPodName")).(string)
				r := ctx.Value(key("client")).(*resources.Resources)

				// Create a monitor-mode policy so the violation is recorded but
				// the command is not blocked (we need it to succeed so exec
				// doesn't error out before the event is emitted).
				policy := &v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: namespace,
					},
					Spec: v1alpha1.WorkloadPolicySpec{
						Mode: "monitor",
						RulesByContainer: map[string]*v1alpha1.WorkloadPolicyRules{
							"ubuntu": {
								Executables: v1alpha1.WorkloadPolicyExecutables{
									Allowed: []string{
										"/usr/bin/ls",
										"/usr/bin/bash",
										"/usr/bin/sleep",
									},
								},
							},
						},
					},
				}

				t.Log("creating workload policy and waiting for it to become Active")
				createWorkloadPolicy(ctx, t, policy.DeepCopy())

				t.Log("executing disallowed command to trigger a violation")
				var stdout, stderr bytes.Buffer
				err := r.ExecInPod(ctx, namespace, expectedPodName, "ubuntu",
					[]string{"/usr/bin/sh", "-c", "/usr/bin/apt update"}, &stdout, &stderr)
				require.NoError(t, err)

				// Wait for the violation to appear in WorkloadPolicy status first.
				// This confirms the gRPC scrape path works and gives the OTEL
				// pipeline enough time to process the event.
				t.Log("waiting for violation to appear in WorkloadPolicy status")
				policyToCheck := &v1alpha1.WorkloadPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: namespace,
					},
				}
				err = wait.For(conditions.New(r).ResourceMatch(policyToCheck, func(obj k8s.Object) bool {
					wp, ok := obj.(*v1alpha1.WorkloadPolicy)
					if !ok || len(wp.Status.Violations) == 0 {
						return false
					}
					for _, v := range wp.Status.Violations {
						if v.ExecutablePath == "/usr/bin/apt" &&
							v.Action == policymode.MonitorString &&
							v.PodName == expectedPodName {
							return true
						}
					}
					return false
				}), wait.WithTimeout(DefaultOperationTimeout))
				require.NoError(t, err, "violation should appear in WorkloadPolicy status")

				// Now query the OTEL collector Prometheus endpoint for the
				// runtime_enforcer_violations_total metric.
				t.Log("querying OTEL collector Prometheus endpoint for violation metrics")

				collectorPodName, err := findPod(ctx, runtimeEnforcerNamespace, otelCollectorDeploymentName)
				require.NoError(t, err, "should find OTEL collector pod")

				localPort, stopCh, err := portForwardPod(
					config, runtimeEnforcerNamespace, collectorPodName, 9090,
				)
				require.NoError(t, err, "should port-forward to collector prometheus port")
				defer close(stopCh)

				promURL := fmt.Sprintf("http://localhost:%d/metrics", localPort)

				// Poll the Prometheus endpoint until the violation metric appears.
				// The OTEL pipeline is asynchronous: the agent batches events, the
				// collector processes them through the count connector and
				// deltatocumulative processor before they appear on /metrics.
				var metricsBody string
				require.Eventually(t, func() bool {
					body, fetchErr := fetchURL(promURL)
					if fetchErr != nil {
						t.Logf("failed to fetch metrics: %v", fetchErr)
						return false
					}
					metricsBody = body
					return strings.Contains(body, "runtime_enforcer_violations")
				}, DefaultOperationTimeout, 2*time.Second,
					"runtime_enforcer_violations metric should appear on the collector Prometheus endpoint",
				)

				// Validate the metric has the expected labels from the count
				// connector configuration.
				t.Log("validating metric labels")
				assertMetricHasLabel(t, metricsBody, "runtime_enforcer_violations", "policy_name", "test-policy")
				assertMetricHasLabel(t, metricsBody, "runtime_enforcer_violations", "k8s_namespace_name", namespace)
				assertMetricHasLabel(t, metricsBody, "runtime_enforcer_violations", "action", policymode.MonitorString)
				// node_name is set dynamically; just verify the label is present.
				assertMetricHasLabelKey(t, metricsBody, "runtime_enforcer_violations", "node_name")

				deleteWorkloadPolicy(ctx, t, policy.DeepCopy())

				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			t.Log("uninstalling test resources")
			namespace := ctx.Value(key("namespace")).(string)
			r := ctx.Value(key("client")).(*resources.Resources)
			err := decoder.DeleteWithManifestDir(
				ctx, r,
				"./testdata",
				"ubuntu-deployment.yaml",
				[]resources.DeleteOption{},
				decoder.MutateNamespace(namespace),
			)
			assert.NoError(t, err, "failed to delete test data")

			return ctx
		}).Feature()
}

// portForwardPod creates a port-forward to a pod and returns the local port,
// a stop channel (close to terminate), and any error.
func portForwardPod(
	config *envconf.Config,
	namespace, podName string,
	remotePort int,
) (int, chan struct{}, error) {
	restConfig := config.Client().RESTConfig()

	restClient, err := rest.RESTClientFor(
		&rest.Config{
			Host:            restConfig.Host,
			TLSClientConfig: restConfig.TLSClientConfig,
			BearerToken:     restConfig.BearerToken,
			BearerTokenFile: restConfig.BearerTokenFile,
			APIPath:         "/api",
			ContentConfig: rest.ContentConfig{
				GroupVersion:         &schema.GroupVersion{Version: "v1"},
				NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
			},
		},
	)
	if err != nil {
		return 0, nil, fmt.Errorf("creating REST client: %w", err)
	}

	url := restClient.
		Post().
		Resource("pods").
		Namespace(namespace).
		Name(podName).
		SubResource("portforward").
		URL()

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return 0, nil, fmt.Errorf("creating round tripper: %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, url)

	stopCh := make(chan struct{})
	readyCh := make(chan struct{})

	// port 0 means "pick a free port"
	ports := []string{fmt.Sprintf("0:%d", remotePort)}
	fw, err := portforward.New(dialer, ports, stopCh, readyCh, io.Discard, io.Discard)
	if err != nil {
		return 0, nil, fmt.Errorf("creating port forwarder: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- fw.ForwardPorts()
	}()

	select {
	case <-readyCh:
	case fwErr := <-errCh:
		return 0, nil, fmt.Errorf("port forward failed: %w", fwErr)
	case <-time.After(10 * time.Second):
		close(stopCh)
		return 0, nil, errors.New("timed out waiting for port forward to be ready")
	}

	forwardedPorts, err := fw.GetPorts()
	if err != nil {
		close(stopCh)
		return 0, nil, fmt.Errorf("getting forwarded ports: %w", err)
	}

	return int(forwardedPorts[0].Local), stopCh, nil
}

// fetchURL performs an HTTP GET and returns the response body as a string.
func fetchURL(url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// assertMetricHasLabel checks that a Prometheus exposition format body contains
// a metric line with the given label key=value pair.
func assertMetricHasLabel(t *testing.T, body, metricName, labelKey, labelValue string) {
	t.Helper()

	expected := fmt.Sprintf(`%s="%s"`, labelKey, labelValue)
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, metricName) && strings.Contains(line, expected) {
			return
		}
	}
	assert.Failf(t, "metric label not found",
		"expected metric %q to have label %s=%q", metricName, labelKey, labelValue)
}

// assertMetricHasLabelKey checks that a Prometheus exposition format body
// contains a metric line with the given label key (any value).
func assertMetricHasLabelKey(t *testing.T, body, metricName, labelKey string) {
	t.Helper()

	needle := labelKey + `="`
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, metricName) && strings.Contains(line, needle) {
			return
		}
	}
	assert.Failf(t, "metric label key not found",
		"expected metric %q to have label key %q", metricName, labelKey)
}
