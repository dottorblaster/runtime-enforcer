package main

import (
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

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

	// Disable Cobra’s built-in "completion" command.
	cmd.CompletionOptions.DisableDefaultCmd = true

	// Custom usage template: no "kubectl [command]" line.
	cmd.SetUsageTemplate(`Usage:
  {{.UseLine}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}  {{rpad .Name .NamePadding}} {{.Short}}
{{end}}{{end}}
Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
`)

	cmd.AddCommand(newMarkReadyCmd())

	return cmd
}

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
