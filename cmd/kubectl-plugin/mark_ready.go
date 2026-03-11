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
)

type markReadyOptions struct {
	commonOptions

	ProposalName string
}

func newMarkReadyCmd() *cobra.Command {
	opts := &markReadyOptions{}

	cmd := &cobra.Command{
		Use:   "mark-ready PROPOSAL_NAME",
		Short: "Mark WorkloadPolicyProposal as ready",
		Long:  "Mark WorkloadPolicyProposal as ready. This will trigger the creation of a WorkloadPolicy.",
		Args:  cobra.ExactArgs(1),
		RunE:  runMarkReadyCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	cmd.Flags().StringVarP(&opts.Namespace, "namespace", "n", "", "Namespace of the WorkloadPolicyProposal")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")

	return cmd
}

func runMarkReadyCmd(opts *markReadyOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.ProposalName = args[0]

		return withRuntimeEnforcerClient(cmd, opts.Namespace, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
			namespace string,
		) error {
			opts.Namespace = namespace
			return runMarkReady(ctx, securityClient, opts, cmd.OutOrStdout())
		})
	}
}

func runMarkReady(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *markReadyOptions,
	out io.Writer,
) error {
	proposal, err := client.WorkloadPolicyProposals(opts.Namespace).Get(ctx, opts.ProposalName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("workloadpolicyproposal %q not found in namespace %q", opts.ProposalName, opts.Namespace)
		}
		return fmt.Errorf(
			"failed to get WorkloadPolicyProposal %q in namespace %q: %w",
			opts.ProposalName,
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
		return nil
	}

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

	policy, err := waitForWorkloadPolicy(ctx, client, opts.Namespace, opts.ProposalName)
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
	ticker := time.NewTicker(defaultPollInterval)
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
