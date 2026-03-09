package main

import (
	"context"
	"fmt"
	"io"
	"time"

	apiv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	securityclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

type markReadyOptions struct {
	PolicyName string
	Namespace  string
	DryRun     bool
}

const (
	markReadyTimeout      = 30 * time.Second
	markReadyPollInterval = 500 * time.Millisecond
)

func newMarkReadyCmd() *cobra.Command {
	opts := &markReadyOptions{}

	cmd := &cobra.Command{
		Use:   "mark-ready PROPOSAL_NAME",
		Short: "Mark WorkloadPolicyProposal as ready",
		Long:  "Mark WorkloadPolicyProposal as ready. This will trigger the creation of a WorkloadPolicy.",
		Args:  cobra.ExactArgs(1),
		RunE:  runMarkReadyCmd(opts),
	}

	// Custom usage template for this leaf command: no “Available Commands”.
	cmd.SetUsageTemplate(`Usage:
  {{.UseLine}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`)

	cmd.Flags().StringVarP(&opts.Namespace, "namespace", "n", "", "Namespace of the WorkloadPolicyProposal")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")

	return cmd
}

func runMarkReadyCmd(opts *markReadyOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.PolicyName = args[0]

		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		overrides := &clientcmd.ConfigOverrides{}
		if opts.Namespace != "" {
			overrides.Context.Namespace = opts.Namespace
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
		opts.Namespace = namespace

		securityClient, err := securityclient.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("failed to create runtime-enforcer client: %w", err)
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), markReadyTimeout)
		defer cancel()

		return runMarkReady(ctx, securityClient, opts, cmd.OutOrStdout())
	}
}

func runMarkReady(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *markReadyOptions,
	out io.Writer,
) error {
	proposal, err := client.WorkloadPolicyProposals(opts.Namespace).Get(ctx, opts.PolicyName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("workloadpolicyproposal %q not found in namespace %q", opts.PolicyName, opts.Namespace)
		}
		return fmt.Errorf(
			"failed to get WorkloadPolicyProposal %q in namespace %q: %w",
			opts.PolicyName,
			opts.Namespace,
			err,
		)
	}

	if opts.DryRun {
		fmt.Fprintf(out, "Would mark WorkloadPolicyProposal %q in namespace %q as ready by setting label %q: %q.\n",
			proposal.Name, proposal.Namespace, apiv1alpha1.ApprovalLabelKey, "true")
		fmt.Fprintf(out, "This will trigger the creation of a WorkloadPolicy %q in namespace %q.\n",
			proposal.Name, proposal.Namespace)
		return nil
	}

	labels := proposal.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}

	if labels[apiv1alpha1.ApprovalLabelKey] == "true" {
		fmt.Fprintf(
			out,
			"WorkloadPolicyProposal %q in namespace %q is already marked as ready.\n",
			proposal.Name,
			proposal.Namespace,
		)
	} else {
		labels[apiv1alpha1.ApprovalLabelKey] = "true"
		proposal.SetLabels(labels)

		if _, err = client.WorkloadPolicyProposals(opts.Namespace).
			Update(ctx, proposal, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsConflict(err) {
				return fmt.Errorf(
					"WorkloadPolicyProposal %q in namespace %q was modified concurrently",
					proposal.Name,
					proposal.Namespace,
				)
			}
			return fmt.Errorf(
				"failed to update WorkloadPolicyProposal %q in namespace %q: %w",
				proposal.Name,
				proposal.Namespace,
				err,
			)
		}

		fmt.Fprintf(
			out,
			"Marked WorkloadPolicyProposal %q in namespace %q as ready.\n",
			proposal.Name,
			proposal.Namespace,
		)
	}

	policy, err := waitForWorkloadPolicy(ctx, client, opts.Namespace, opts.PolicyName)
	if err != nil {
		return fmt.Errorf("policy promotion did not complete successfully: %w", err)
	}

	fmt.Fprintf(out, "WorkloadPolicy %q in namespace %q has been created.\n", policy.Name, policy.Namespace)

	return nil
}

func waitForWorkloadPolicy(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	namespace, name string,
) (*apiv1alpha1.WorkloadPolicy, error) {
	ticker := time.NewTicker(markReadyPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf(
				"stopped waiting for WorkloadPolicy %q in namespace %q to be created: %w",
				name,
				namespace,
				ctx.Err(),
			)
		case <-ticker.C:
			policy, err := client.WorkloadPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, fmt.Errorf("failed to get WorkloadPolicy %q in namespace %q: %w", name, namespace, err)
			}

			return policy, nil
		}
	}
}
