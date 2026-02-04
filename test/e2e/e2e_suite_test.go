package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

//nolint:gochecknoglobals // provided by e2e-framework
var (
	testEnv         env.Environment
	kindClusterName string
	namespace       string
	otelNamespace   string
)

const (
	certManagerHelmRepoName = "jetstack-e2e-test"
	otelHelmRepoName        = "otel-e2e-test"

	certManagerVersion          = "v1.18.2"
	otelVersion                 = "v0.136.0"
	certManagerCSIDriverVersion = "v0.12.0"

	// at the moment `third_party/helm` doesn't expose a way to check if a repo exists.
	helmRepoNotFoundString = "no repo named"
)

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testEnv = env.NewWithConfig(cfg)
	kindClusterName = envconf.RandomName("test-controller-e2e", 32)
	namespace = envconf.RandomName("enforcer-namespace", 16)
	otelNamespace = envconf.RandomName("otel", 16)

	testEnv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
		envfuncs.CreateNamespace(namespace),
		envfuncs.LoadImageToCluster(kindClusterName,
			"ghcr.io/rancher-sandbox/runtime-enforcer/operator:latest",
			"--verbose",
			"--mode",
			"direct"),
		envfuncs.LoadImageToCluster(kindClusterName,
			"ghcr.io/rancher-sandbox/runtime-enforcer/agent:latest",
			"--verbose",
			"--mode",
			"direct"),
		removeHelmRepos(),
		InstallOtelCollector(),
		InstallCertManager(),
		InstallRuntimeEnforcer(),
	)

	testEnv.Finish(
		envfuncs.ExportClusterLogs(kindClusterName, "./logs"),
		envfuncs.DeleteNamespace(namespace),
		envfuncs.DestroyCluster(kindClusterName),
		removeHelmRepos(),
	)

	os.Exit(testEnv.Run(m))
}

func removeHelmRepos() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		for _, repo := range []string{certManagerHelmRepoName, otelHelmRepoName} {
			err := manager.RunRepo(helm.WithArgs("remove", repo))
			if err != nil && !strings.Contains(err.Error(), helmRepoNotFoundString) {
				logger.Info("failed to remove helm repo",
					"repo", repo,
					"error", err)
			}
		}
		return ctx, nil
	}
}

func InstallCertManager() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())

		err := manager.RunRepo(helm.WithArgs("add", certManagerHelmRepoName, "https://charts.jetstack.io"))
		if err != nil {
			return ctx, fmt.Errorf("failed to add cert manager repo: %w", err)
		}
		err = manager.RunRepo(helm.WithArgs("update"))
		if err != nil {
			return ctx, fmt.Errorf("failed to update cert manager repo: %w", err)
		}

		// Install cert-manager
		err = manager.RunInstall(
			helm.WithName("cert-manager"),
			helm.WithChart(certManagerHelmRepoName+"/cert-manager"),
			helm.WithNamespace("cert-manager"),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--version", certManagerVersion),
			helm.WithArgs("--set", "installCRDs=true"),
			helm.WithWait(),
			helm.WithTimeout(DefaultHelmTimeout.String()))
		if err != nil {
			return ctx, fmt.Errorf("failed to install cert manager: %w", err)
		}

		// Install cert-manager CSI driver
		err = manager.RunInstall(
			helm.WithName("cert-manager-csi-driver"),
			helm.WithChart(certManagerHelmRepoName+"/cert-manager-csi-driver"),
			helm.WithNamespace("cert-manager"),
			helm.WithArgs("--version", certManagerCSIDriverVersion),
			helm.WithWait(),
			helm.WithTimeout(DefaultHelmTimeout.String()))
		if err != nil {
			return ctx, fmt.Errorf("failed to install cert manager CSI driver: %w", err)
		}

		return ctx, nil
	}
}

func InstallRuntimeEnforcer() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		err := manager.RunInstall(
			helm.WithName("runtime-enforcer"),
			helm.WithNamespace(namespace),
			helm.WithChart("../../charts/runtime-enforcer/"),
			helm.WithArgs("--set", "operator.manager.image.tag=latest"),
			helm.WithArgs("--set", "agent.agent.image.tag=latest"),
			helm.WithArgs("--set", "telemetry.mode=custom"),
			helm.WithArgs("--set", "telemetry.tracing=true"),
			// we need to reduce the timeout to see the wp status controller working properly in e2e tests
			helm.WithArgs("--set", "operator.manager.wpStatusUpdateInterval=2s"),
			helm.WithArgs(
				"--set",
				"telemetry.custom.endpoint=http://open-telemetry-collector-opentelemetry-collector."+otelNamespace+".svc.cluster.local:4317",
			),
			helm.WithArgs("--set", "telemetry.custom.insecure=true"),
			helm.WithWait(),
			helm.WithTimeout(DefaultHelmTimeout.String()),
		)

		if err != nil {
			return ctx, fmt.Errorf("failed to install Runtime Enforcer: %w", err)
		}
		return ctx, nil
	}
}

func InstallOtelCollector() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())

		err := manager.RunRepo(
			helm.WithArgs("add", otelHelmRepoName, "http://open-telemetry.github.io/opentelemetry-helm-charts"),
		)
		if err != nil {
			return ctx, fmt.Errorf("failed to add otel collector repo: %w", err)
		}
		err = manager.RunRepo(helm.WithArgs("update"))
		if err != nil {
			return ctx, fmt.Errorf("failed to update otel collector repo: %w", err)
		}

		// Install otel collector
		err = manager.RunInstall(
			helm.WithName("open-telemetry-collector"),
			helm.WithChart(otelHelmRepoName+"/opentelemetry-collector"),
			helm.WithNamespace(otelNamespace),
			helm.WithArgs("--create-namespace"),
			helm.WithArgs("--version", otelVersion),
			helm.WithArgs("--set image.repository=otel/opentelemetry-collector-k8s"),
			helm.WithArgs("--set mode=deployment"),
			helm.WithArgs("--set config.exporters.file.path=/dev/stdout"),
			helm.WithArgs("--set config.service.pipelines.traces.exporters[0]=file"),
			helm.WithArgs("--set config.service.pipelines.metrics=null"),
			helm.WithArgs("--set config.service.pipelines.logs=null"),
			helm.WithWait(),
			helm.WithTimeout(DefaultHelmTimeout.String()))
		if err != nil {
			return ctx, fmt.Errorf("failed to install otel collector: %w", err)
		}

		return ctx, nil
	}
}
