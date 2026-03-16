package main

import (
	"context"
	"fmt"
	"os"
	"time"

	securityclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// groupUsageTemplate is a custom usage template for group commands (e.g. "proposal", "policy").
const groupUsageTemplate = `Usage:
  {{.UseLine}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}  {{rpad .Name .NamePadding}} {{.Short}}
{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

// subcommandUsageTemplate is a custom usage template for subcommands:
// it does not print the "Available Commands" section.
const subcommandUsageTemplate = `Usage:
  {{.UseLine}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`

const (
	defaultOperationTimeout = 30 * time.Second
	defaultPollInterval     = 500 * time.Millisecond
)

type commonOptions struct {
	configFlags *genericclioptions.ConfigFlags
	ioStreams   genericclioptions.IOStreams

	Namespace string
	DryRun    bool
}

func newCommonOptions() commonOptions {
	return commonOptions{
		configFlags: genericclioptions.NewConfigFlags(true),
		ioStreams:   genericclioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	}
}

type subcommandFunc func(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
) error

type subcommandWithCoreFunc func(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
	coreClient corev1client.CoreV1Interface,
) error

// buildSecurityClient resolves the namespace, builds the REST config and creates the runtime-enforcer security client.
// It also populates opts.Namespace as a side effect.
func buildSecurityClient(opts *commonOptions) (securityclient.SecurityV1alpha1Interface, error) {
	namespace, _, err := opts.configFlags.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return nil, fmt.Errorf("failed to determine namespace: %w", err)
	}
	opts.Namespace = namespace

	config, err := opts.configFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes configuration: %w", err)
	}

	securityClient, err := securityclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create runtime-enforcer client: %w", err)
	}

	return securityClient, nil
}

// withRuntimeEnforcerClient is a helper function to create a runtime-enforcer client and execute a subcommand.
func withRuntimeEnforcerClient(
	cmd *cobra.Command,
	opts *commonOptions,
	subcommand subcommandFunc,
) error {
	securityClient, err := buildSecurityClient(opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), defaultOperationTimeout)
	defer cancel()

	return subcommand(ctx, securityClient)
}

// withRuntimeEnforcerAndCoreClient is a helper function to create a runtime-enforcer and Kubernetes core client.
func withRuntimeEnforcerAndCoreClient(
	cmd *cobra.Command,
	opts *commonOptions,
	subcommand subcommandWithCoreFunc,
) error {
	securityClient, err := buildSecurityClient(opts)
	if err != nil {
		return err
	}

	config, err := opts.configFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build Kubernetes configuration: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), defaultOperationTimeout)
	defer cancel()

	return subcommand(ctx, securityClient, kubeClient.CoreV1())
}
