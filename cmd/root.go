package cmd

import (
	"os"

	"github.com/dadrus/heimdall/version"
	"github.com/spf13/cobra"
)

// nolint: gochecknoglobals
var (
	// RootCmd represents the base command when called without any subcommands.
	RootCmd = &cobra.Command{
		Use:     "heimdall",
		Short:   "A cloud native Access and Identity Proxy",
		Version: version.Version,
	}
)

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		RootCmd.PrintErr(err)
		os.Exit(-1)
	}
}
