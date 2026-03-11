package main

import (
	"context"
	"fmt"
	"time"

	securityclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
)

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
	Namespace string
	DryRun    bool
}

type subcommandFunc func(
	ctx context.Context,
	securityClient securityclient.SecurityV1alpha1Interface,
	namespace string,
) error

// withRuntimeEnforcerClient is a helper function to create a runtime-enforcer client and execute a subcommand.
func withRuntimeEnforcerClient(
	cmd *cobra.Command,
	ns string,
	subcommand subcommandFunc,
) error {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if ns != "" {
		overrides.Context.Namespace = ns
	}

	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to load Kubernetes configuration: %w", err)
	}

	namespace, _, err := kubeConfig.Namespace()
	if err != nil {
		return fmt.Errorf("failed to determine namespace: %w", err)
	}

	securityClient, err := securityclient.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create runtime-enforcer client: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), defaultOperationTimeout)
	defer cancel()

	return subcommand(ctx, securityClient, namespace)
}
