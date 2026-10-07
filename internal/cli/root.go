// Package cli wires the dpiprisma command tree.
package cli

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"
)

// Execute runs the dpiprisma command line with the given build version.
func Execute(version string) error {
	return newRootCmd(version).Execute()
}

// newRootCmd builds the dpiprisma command tree.
func newRootCmd(version string) *cobra.Command {
	var verbose bool // set by the --verbose flag

	root := &cobra.Command{
		Use:           "dpiprisma",
		Short:         "Diagnose how DPI blocks a domain on your network",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			slog.SetDefault(newLogger(cmd.ErrOrStderr(), verbose))
			slog.Debug("starting", "version", version, "command", cmd.Name())
			return nil
		},
	}

	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "print debug logs")
	root.SetVersionTemplate("dpiprisma {{.Version}}\n")
	root.AddCommand(newVersionCmd(version))
	root.AddCommand(newScanCmd())
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

// newLogger returns a text logger writing to w. It prints debug messages
// only when verbose is true; otherwise only warnings and errors.
func newLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}
