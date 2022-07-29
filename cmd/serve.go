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

	serveCmd.PersistentFlags().StringP("config", "c", "", "Config file")
	serveCmd.AddCommand(serve.NewProxyCommand())
	serveCmd.AddCommand(serve.NewDecisionCommand())
}
