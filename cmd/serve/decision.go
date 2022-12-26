package serve

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/decision"
)

// NewDecisionCommand represents the "serve decision" command.
func NewDecisionCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "decision",
		Short:   "Starts heimdall in Decision operation mode",
		Example: "heimdall serve decision",
		Run: func(cmd *cobra.Command, _ []string) {
			app, err := createDecisionApp(cmd)
			if err != nil {
				cmd.PrintErrf("Failed to initialize decision service: %v", err)
				panic(err)
			}

			app.Run()
		},
	}
}

func createDecisionApp(cmd *cobra.Command) (*fx.App, error) {
	configPath, _ := cmd.Flags().GetString("config")
	envPrefix, _ := cmd.Flags().GetString("env-config-prefix")

	app := fx.New(
		fx.NopLogger,
		fx.Supply(
			config.ConfigurationPath(configPath),
			config.EnvVarPrefix(envPrefix)),
		internal.Module,
		decision.Module,
	)

	return app, app.Err()
}
