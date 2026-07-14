package kubectlplugin

import (
	"github.com/spf13/cobra"
)

func newPolicyCmd(deps commonCmdDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage WorkloadPolicy",
	}

	cmd.SetUsageTemplate(groupUsageTemplate)

	cmd.AddCommand(newPolicyModeProtectCmd(deps))
	cmd.AddCommand(newPolicyModeMonitorCmd(deps))
	cmd.AddCommand(newPolicyShowCmd(deps))
	cmd.AddCommand(newPolicyExecAllowCmd(deps))
	cmd.AddCommand(newPolicyExecDenyCmd(deps))
	cmd.AddCommand(newPolicyAckCmd(deps))

	return cmd
}
