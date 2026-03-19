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

type proposalPromoteOptions struct {
	commonOptions

	ProposalName string
}

func newProposalPromoteCmd() *cobra.Command {
	opts := &proposalPromoteOptions{
		commonOptions: newCommonOptions(),
	}

	cmd := &cobra.Command{
		Use:   "promote PROPOSAL_NAME",
		Short: "Promote WorkloadPolicyProposal to WorkloadPolicy",
		Long:  "Promote WorkloadPolicyProposal to WorkloadPolicy. This will trigger the creation of a WorkloadPolicy.",
		Args:  cobra.ExactArgs(1),
		RunE:  runProposalPromoteCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	// Standard kube flags (adds --namespace, --kubeconfig, --context, etc.)
	opts.configFlags.AddFlags(cmd.Flags())

	// Plugin-specific flags
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")

	return cmd
}

func runProposalPromoteCmd(opts *proposalPromoteOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.ProposalName = args[0]

		return withRuntimeEnforcerClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			client securityclient.SecurityV1alpha1Interface,
		) error {
			return runProposalPromote(ctx, client, opts, opts.ioStreams.Out)
		})
	}
}

func runProposalPromote(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *proposalPromoteOptions,
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

	labels := proposal.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}

	if labels[apiv1alpha1.ApprovalLabelKey] == "true" {
		fmt.Fprintf(
			out,
			"WorkloadPolicyProposal %q in namespace %q is already promoted to WorkloadPolicy.\n",
			proposal.Name,
			proposal.Namespace,
		)
		return nil
	}

	updateOptions := metav1.UpdateOptions{}
	if opts.DryRun {
		fmt.Fprintf(
			out,
			"Would promote WorkloadPolicyProposal %q in namespace %q to WorkloadPolicy by setting label %q: %q.\n",
			proposal.Name,
			proposal.Namespace,
			apiv1alpha1.ApprovalLabelKey,
			"true",
		)
		fmt.Fprintf(
			out,
			"This will trigger the creation of a WorkloadPolicy %q in namespace %q.\n",
			proposal.Name,
			proposal.Namespace,
		)
		updateOptions.DryRun = []string{metav1.DryRunAll}
	}

	labels[apiv1alpha1.ApprovalLabelKey] = "true"
	proposal.SetLabels(labels)

	if _, err = client.WorkloadPolicyProposals(opts.Namespace).
		Update(ctx, proposal, updateOptions); err != nil {
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
		"Promoted WorkloadPolicyProposal %q in namespace %q to WorkloadPolicy.\n",
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
