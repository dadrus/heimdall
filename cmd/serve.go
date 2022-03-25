package cmd

import (
	"github.com/dadrus/heimdall/cmd/serve"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starts the HTTP/2 REST API and HTTP/2 Reverse Proxy",
	Long: `Opens two ports for serving both the HTTP/2 Rest API and the HTTP/2 Reverse Proxy.

## Configuration

Heimdall can be configured using environment variables as well as a configuration file. For more information
on configuration options, open the configuration documentation:

>> https://www.ory.sh/oathkeeper/docs/configuration <<
`,
}

func init() {
	RootCmd.AddCommand(serveCmd)

	serveCmd.PersistentFlags().Bool("disable-telemetry", false, "Disable anonymized telemetry reports - for more information please visit https://www.ory.sh/docs/ecosystem/sqa")
	serveCmd.PersistentFlags().StringP("config", "c", "", "Config file")
	serveCmd.AddCommand(serve.NewProxyCommand())
	serveCmd.AddCommand(serve.NewDecisionApiCommand())
	serveCmd.AddCommand(serve.NewAllServicesCommand())
}
