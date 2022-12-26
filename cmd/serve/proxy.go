package serve

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/proxy"
)

// NewProxyCommand represents the proxy command.
func NewProxyCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "proxy",
		Short:   "Starts heimdall in Reverse Proxy operation mode",
		Example: "heimdall serve proxy",
		Run: func(cmd *cobra.Command, _ []string) {
			app, err := createProxyApp(cmd)
			if err != nil {
				cmd.PrintErrf("Failed to initialize proxy service: %v", err)
				panic(err)
			}

			app.Run()
		},
	}
}

func createProxyApp(cmd *cobra.Command) (*fx.App, error) {
	configPath, _ := cmd.Flags().GetString("config")
	envPrefix, _ := cmd.Flags().GetString("env-config-prefix")

	app := fx.New(
		fx.NopLogger,
		fx.Supply(
			config.ConfigurationPath(configPath),
			config.EnvVarPrefix(envPrefix)),
		internal.Module,
		proxy.Module,
	)

	return app, app.Err()
}
