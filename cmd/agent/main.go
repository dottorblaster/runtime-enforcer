package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
	"github.com/rancher-sandbox/runtime-enforcer/internal/bpf"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventhandler"
	"github.com/rancher-sandbox/runtime-enforcer/internal/eventscraper"
	"github.com/rancher-sandbox/runtime-enforcer/internal/grpcexporter"
	"github.com/rancher-sandbox/runtime-enforcer/internal/nri"
	"github.com/rancher-sandbox/runtime-enforcer/internal/resolver"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/rancher-sandbox/runtime-enforcer/internal/traces"
	"k8s.io/api/node/v1alpha1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"log/slog"
)

type Config struct {
	enableTracing     bool
	enableOtelSidecar bool
	enableLearning    bool
	nriSocketPath     string
	nriPluginIdx      string
	probeAddr         string
	grpcConf          grpcexporter.Config
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch

func newControllerManager(config Config) (manager.Manager, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	controllerOptions := ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: config.probeAddr,
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), controllerOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to start manager: %w", err)
	}
	return mgr, nil
}

func setupGRPCExporter(
	ctrlMgr manager.Manager,
	logger *slog.Logger,
	conf *grpcexporter.Config,
	r *resolver.Resolver,
) error {
	exporter, err := grpcexporter.New(logger, conf, r)
	if err != nil {
		return fmt.Errorf("failed to create gRPC exporter: %w", err)
	}
	if err = ctrlMgr.Add(exporter); err != nil {
		return fmt.Errorf("failed to add gRPC exporter to controller manager: %w", err)
	}
	return nil
}

func setupLearningReconciler(
	ctx context.Context,
	logger *slog.Logger,
	config Config,
	ctrlMgr manager.Manager,
) (func(eventscraper.KubeProcessInfo), error) {
	if !config.enableLearning {
		logger.InfoContext(ctx, "learning mode is disabled")
		return func(_ eventscraper.KubeProcessInfo) {
			panic("enqueue function should be never called when learning is disabled")
		}, nil
	}

	learningReconciler := eventhandler.NewLearningReconciler(ctrlMgr.GetClient())
	if err := learningReconciler.SetupWithManager(ctrlMgr); err != nil {
		return nil, fmt.Errorf("unable to create learning reconciler: %w", err)
	}
	logger.InfoContext(ctx, "learning mode is enabled")
	return learningReconciler.EnqueueEvent, nil
}

func setupPolicyInformer(
	ctx context.Context,
	logger *slog.Logger,
	ctrlMgr manager.Manager,
	resolver *resolver.Resolver,
) error {
	workloadPolicyInformer, err := ctrlMgr.GetCache().GetInformer(ctx, &securityv1alpha1.WorkloadPolicy{})
	if err != nil {
		return fmt.Errorf("cannot get workload policy informer: %w", err)
	}
	handlerRegistration, err := workloadPolicyInformer.AddEventHandler(resolver.PolicyEventHandlers())
	if err != nil {
		return fmt.Errorf("failed to add event handler for workload policy: %w", err)
	}

	// controller-runtime doesn't support a separate startup probe, so we use the readiness probe instead.
	// See https://github.com/kubernetes-sigs/controller-runtime/issues/2644 for more details.
	if err = ctrlMgr.AddReadyzCheck("policy readyz", func(_ *http.Request) error {
		// Instead of informer.HasSynced(), which checks if the internal storage is synced,
		// we use ResourceEventHandlerRegistration.HasSynced() to ensure that
		// the event handlers have been synced.
		if !handlerRegistration.HasSynced() {
			logger.Warn("workload policy informer has not yet synced")
			return errors.New("workload policy informer has not yet synced")
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to add policy readiness probe: %w", err)
	}
	return nil
}

func startAgent(ctx context.Context, logger *slog.Logger, config Config) error {
	var err error

	//////////////////////
	// Create controller manager
	//////////////////////
	ctrlMgr, err := newControllerManager(config)
	if err != nil {
		return fmt.Errorf("cannot create manager: %w", err)
	}

	//////////////////////
	// Create BPF manager
	//////////////////////
	bpfManager, err := bpf.NewManager(logger, config.enableLearning, ebpf.LogLevelBranch)
	if err != nil {
		return fmt.Errorf("cannot create BPF manager: %w", err)
	}
	if err = ctrlMgr.Add(bpfManager); err != nil {
		return fmt.Errorf("failed to add BPF manager to controller manager: %w", err)
	}

	//////////////////////
	// Create Learning Reconciler if learning is enabled
	//////////////////////
	enqueueFunc, err := setupLearningReconciler(ctx, logger, config, ctrlMgr)
	if err != nil {
		return err
	}

	//////////////////////
	// Create the resolver
	//////////////////////
	resolver, err := resolver.NewResolver(
		logger,
		bpfManager.GetCgroupTrackerUpdateFunc(),
		bpfManager.GetCgroupPolicyUpdateFunc(),
		bpfManager.GetPolicyUpdateBinariesFunc(),
		bpfManager.GetPolicyModeUpdateFunc(),
	)
	if err != nil {
		return fmt.Errorf("failed to create resolver: %w", err)
	}

	var nriHandler *nri.Handler
	nriHandler, err = nri.NewNRIHandler(
		config.nriSocketPath,
		config.nriPluginIdx,
		logger,
		resolver,
	)
	if err != nil {
		return fmt.Errorf("failed to create NRI handler: %w", err)
	}
	if err = ctrlMgr.Add(nriHandler); err != nil {
		return fmt.Errorf("failed to add NRI handler to controller manager: %w", err)
	}

	// controller-runtime doesn't support a separate startup probe, so we use the readiness probe instead.
	// See https://github.com/kubernetes-sigs/controller-runtime/issues/2644 for more details.
	if err = ctrlMgr.AddReadyzCheck("resolver readyz", resolver.Ping); err != nil {
		return fmt.Errorf("failed to add resolver's readiness probe: %w", err)
	}

	//////////////////////
	// Create the scraper
	//////////////////////
	evtScraper := eventscraper.NewEventScraper(
		bpfManager.GetLearningChannel(),
		bpfManager.GetMonitoringChannel(),
		logger,
		resolver,
		enqueueFunc,
	)
	if err = ctrlMgr.Add(evtScraper); err != nil {
		return fmt.Errorf("failed to add event scraper to controller manager: %w", err)
	}

	//////////////////////
	// Setup Policy Generator with the workload informer
	//////////////////////
	if err = setupPolicyInformer(ctx, logger, ctrlMgr, resolver); err != nil {
		return err
	}

	//////////////////////
	// Add GRPC exporter
	//////////////////////
	if err = setupGRPCExporter(ctrlMgr, logger, &config.grpcConf, resolver); err != nil {
		return err
	}

	logger.InfoContext(ctx, "starting manager")
	if err = ctrlMgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start manager: %w", err)
	}

	return nil
}

func main() {
	var err error
	var config Config

	var traceShutdown func(context.Context) error

	ctx := ctrl.SetupSignalHandler()

	flag.BoolVar(&config.enableTracing, "enable-tracing", false, "Enable tracing collection")
	flag.BoolVar(&config.enableOtelSidecar, "enable-otel-sidecar", false, "Enable OpenTelemetry sidecar")
	flag.BoolVar(&config.enableLearning, "enable-learning", false, "Enable learning mode")
	flag.StringVar(&config.nriSocketPath, "nri-socket-path", "/var/run/nri/nri.sock", "NRI socket path")
	flag.StringVar(&config.nriPluginIdx, "nri-plugin-index", "00", "NRI plugin index")
	flag.StringVar(&config.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.IntVar(&config.grpcConf.Port, "grpc-port", 50051, "gRPC server port")
	flag.BoolVar(&config.grpcConf.MTLSEnabled, "grpc-mtls-enabled", true,
		"Enable mutual TLS between the agent server and clients")
	flag.StringVar(&config.grpcConf.CertDirPath, "grpc-mtls-cert-dir", "",
		"Path to the directory containing the server and ca TLS certificate")
	flag.Parse()

	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slogger := slog.New(slogHandler).With("component", "agent")
	slog.SetDefault(slogger)
	ctrl.SetLogger(logr.FromSlogHandler(slogger.Handler()))

	if config.enableTracing {
		// Start otel traces
		traceShutdown, err = traces.Init()
		if err != nil {
			slogger.ErrorContext(ctx, "failed to initiate open telemetry trace", "error", err)
			os.Exit(1)
		}
	}

	// This function blocks if everything is alright.
	if err = startAgent(ctx, slogger, config); err != nil {
		slogger.ErrorContext(ctx, "failed to start agent", "error", err)
		os.Exit(1)
	}

	if traceShutdown != nil {
		if err = traceShutdown(ctx); err != nil {
			slogger.ErrorContext(ctx, "failed to shutdown telemetry trace", "error", err)
		}
	}
}
