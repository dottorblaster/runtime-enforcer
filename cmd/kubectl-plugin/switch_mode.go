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

type switchModeOptions struct {
	commonOptions

	PolicyName string
	Mode       string
}

func newSwitchModeCmd() *cobra.Command {
	opts := &switchModeOptions{}

	cmd := &cobra.Command{
		Use:   "switch-mode POLICY_NAME",
		Short: "Switch WorkloadPolicy mode between monitor and protect",
		Long:  "Switch WorkloadPolicy mode between monitor and protect without editing YAML manually.",
		Args:  cobra.ExactArgs(1),
		RunE:  runSwitchModeCmd(opts),
	}

	cmd.SetUsageTemplate(subcommandUsageTemplate)

	cmd.Flags().StringVarP(&opts.Namespace, "namespace", "n", "", "Namespace of the WorkloadPolicy")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Show what would happen without making any changes")
	cmd.Flags().StringVarP(&opts.Mode, "mode", "m", "", "Target mode for the WorkloadPolicy")
	_ = cmd.MarkFlagRequired("mode")

	return cmd
}

func runSwitchModeCmd(opts *switchModeOptions) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		opts.PolicyName = args[0]

		if err := validateMode(opts.Mode); err != nil {
			return err
		}

		return withRuntimeEnforcerClient(cmd, opts.Namespace, func(
			ctx context.Context,
			securityClient securityclient.SecurityV1alpha1Interface,
			namespace string,
		) error {
			opts.Namespace = namespace
			return runSwitchMode(ctx, securityClient, opts, cmd.OutOrStdout())
		})
	}
}

func runSwitchMode(
	ctx context.Context,
	client securityclient.SecurityV1alpha1Interface,
	opts *switchModeOptions,
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

	if err = validateMode(currentMode); err != nil {
		return fmt.Errorf(
			"WorkloadPolicy %q in namespace %q has invalid current mode %q, please correct it before using this command",
			policy.Name,
			policy.Namespace,
			currentMode,
		)
	}

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

	if opts.DryRun {
		fmt.Fprintf(
			out,
			"Would switch WorkloadPolicy %q in namespace %q from %q mode to %q mode.\n",
			policy.Name,
			policy.Namespace,
			currentMode,
			targetMode,
		)
		return nil
	}

	policy.Spec.Mode = targetMode

	if _, err = client.WorkloadPolicies(opts.Namespace).
		Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
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
		"Successfully switched WorkloadPolicy %q in namespace %q from %q mode to %q mode.\n",
		policy.Name,
		policy.Namespace,
		currentMode,
		targetMode,
	)

	return nil
}

func validateMode(mode string) error {
	switch mode {
	case policymode.MonitorString, policymode.ProtectString:
		return nil
	default:
		return fmt.Errorf(
			"invalid mode %q, expected %q or %q",
			mode,
			policymode.MonitorString,
			policymode.ProtectString,
		)
	}
}
