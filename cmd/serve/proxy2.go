package serve

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/proxy2"
)

// NewProxyCommand represents the proxy command.
func NewProxy2Command() *cobra.Command {
	return &cobra.Command{
		Use:     "proxy2",
		Short:   "Starts heimdall in Reverse Proxy operation mode",
		Example: "heimdall serve proxy2",
		Run: func(cmd *cobra.Command, _ []string) {
			app, err := createProxy2App(cmd)
			if err != nil {
				cmd.PrintErrf("Failed to initialize proxy service: %v", err)

				os.Exit(1)
			}

			app.Run()
		},
	}
}

func createProxy2App(cmd *cobra.Command) (*fx.App, error) {
	configPath, _ := cmd.Flags().GetString("config")
	envPrefix, _ := cmd.Flags().GetString("env-config-prefix")

	app := fx.New(
		fx.NopLogger,
		fx.Supply(
			config.ConfigurationPath(configPath),
			config.EnvVarPrefix(envPrefix),
			config.ProxyMode),
		internal.Module,
		proxy2.Module,
	)

	return app, app.Err()
}
