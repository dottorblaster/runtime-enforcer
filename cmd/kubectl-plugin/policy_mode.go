package main

import (
	"context"
	"fmt"
	"io"

	"github.com/rancher-sandbox/runtime-enforcer/internal/types/policymode"
	securityclient "github.com/rancher-sandbox/runtime-enforcer/pkg/generated/clientset/versioned/typed/api/v1alpha1"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type policyModeOptions struct {
	commonOptions

	PolicyName string
	Mode       string
}

func newPolicyModeCmd(mode string) *cobra.Command {
	use := fmt.Sprintf("%s POLICY_NAME", mode)
	short := fmt.Sprintf("Set WorkloadPolicy mode to %s", mode)

	opts := &policyModeOptions{
		commonOptions: newCommonOptions(),
		Mode:          mode,
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE:  runPolicyModeSetCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	// Standard kube flags (adds --namespace, --kubeconfig, --context, etc.)
	opts.configFlags.AddFlags(cmd.Flags())

	// Plugin-specific flags
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")

	return cmd
}

func newPolicyModeProtectCmd() *cobra.Command {
	return newPolicyModeCmd(policymode.ProtectString)
}
func newPolicyModeMonitorCmd() *cobra.Command {
	return newPolicyModeCmd(policymode.MonitorString)
}

func runPolicyModeSetCmd(opts *policyModeOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.PolicyName = args[0]

		return withRuntimeEnforcerClient(cmd, &opts.commonOptions, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
		) error {
			return runPolicyModeSet(ctx, securityClient, opts, opts.ioStreams.Out)
		})
	}
}

func runPolicyModeSet(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *policyModeOptions,
	out io.Writer,
) error {
	policy, err := client.WorkloadPolicies(opts.Namespace).Get(ctx, opts.PolicyName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("workloadpolicy %q not found in namespace %q", opts.PolicyName, opts.Namespace)
		}
		return fmt.Errorf(
			"failed to get WorkloadPolicy %q in namespace %q: %w",
			opts.PolicyName,
			opts.Namespace,
			err,
		)
	}

	currentMode := policy.Spec.Mode
	targetMode := opts.Mode

	if currentMode == targetMode {
		fmt.Fprintf(
			out,
			"WorkloadPolicy %q in namespace %q is already in %q mode.\n",
			policy.Name,
			policy.Namespace,
			currentMode,
		)
		return nil
	}

	updateOptions := metav1.UpdateOptions{}
	if opts.DryRun {
		fmt.Fprintf(
			out,
			"Would set WorkloadPolicy %q in namespace %q to %q mode.\n",
			policy.Name,
			policy.Namespace,
			targetMode,
		)
		updateOptions.DryRun = []string{metav1.DryRunAll}
	}

	policy.Spec.Mode = targetMode

	if _, err = client.WorkloadPolicies(opts.Namespace).
		Update(ctx, policy, updateOptions); err != nil {
		if apierrors.IsConflict(err) {
			return fmt.Errorf(
				"WorkloadPolicy %q in namespace %q was modified concurrently",
				policy.Name,
				policy.Namespace,
			)
		}
		return fmt.Errorf(
			"failed to update WorkloadPolicy %q in namespace %q: %w",
			policy.Name,
			policy.Namespace,
			err,
		)
	}

	fmt.Fprintf(
		out,
		"Successfully set WorkloadPolicy %q in namespace %q to %q mode.\n",
		policy.Name,
		policy.Namespace,
		targetMode,
	)

	return nil
}
