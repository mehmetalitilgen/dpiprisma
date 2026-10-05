// Package cli wires the dpiprisma command tree.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Execute runs the dpiprisma command line with the given build version.
func Execute(version string) error {
	return newRootCmd(version).Execute()
}

// newRootCmd builds the dpiprisma command tree.
func newRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "dpiprisma",
		Short:         "Diagnose how DPI blocks a domain on your network",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("dpiprisma {{.Version}}\n")
	root.AddCommand(newVersionCmd(version))
	return root
}

// newVersionCmd builds "dpiprisma version".
func newVersionCmd(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the dpiprisma version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "dpiprisma %s\n", version)
			return err
		},
	}
}
