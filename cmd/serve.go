package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/serve"
)

// nolint: gochecknoglobals
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starts the heimdall in one of its operations modes (decision or proxy)",
}

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(serveCmd)

	serveCmd.PersistentFlags().StringP("config", "c", "",
		"Path to heimdall's configuration file.\n"+
			"If not provided, the lookup sequence is:\n  1. $PWD\n  2. $HOME/.config\n  3. /etc/heimdall/")
	serveCmd.PersistentFlags().String("env-config-prefix", "HEIMDALLCFG_",
		"Prefix for the environment variables to consider for\nloading configuration from")
	serveCmd.AddCommand(serve.NewProxyCommand())
	serveCmd.AddCommand(serve.NewDecisionCommand())
}
