package main

import "github.com/spf13/cobra"

func newPolicyShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show WorkloadPolicy information",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newPolicyShowProtectionCmd())

	return cmd
}
