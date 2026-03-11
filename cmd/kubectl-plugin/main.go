package main

import (
	"os"

	"github.com/spf13/cobra"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var version = "dev"

// Custom usage template: no "kubectl [command]" line.
const (
	rootUsageTemplate = `Usage:
  {{.UseLine}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}  {{rpad .Name .NamePadding}} {{.Short}}
{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "kubectl runtime-enforcer",
		Long:    "Kubernetes plugin for SUSE Security Runtime Enforcer",
		Version: version,
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.SetUsageTemplate(rootUsageTemplate)

	cmd.AddCommand(newMarkReadyCmd())
	cmd.AddCommand(newSwitchModeCmd())

	return cmd
}

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
