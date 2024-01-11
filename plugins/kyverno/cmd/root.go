package cmd

import (
	"github.com/spf13/cobra"
)

// NewCLI creates a new instance of the root CLI
func NewCLI() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "kyverno-plugin",
	}

	rootCmd.AddCommand(newRunCMD())

	return rootCmd
}
