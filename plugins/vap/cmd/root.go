package cmd

import "github.com/spf13/cobra"

// NewCLI builds the vap-plugin root command.
func NewCLI(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "vap-plugin",
		Short:         "Persists ValidatingAdmissionPolicy audit results as openreports.io Reports",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newRunCommand())
	root.AddCommand(newVersionCommand(version))

	return root
}
