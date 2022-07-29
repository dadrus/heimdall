package serve

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/handler/decision"
)

// NewDecisionCommand represents the "serve decision" command.
func NewDecisionCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "decision",
		Short:   "Starts heimdall in Decision operation mode",
		Example: "heimdall serve decision",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")

			app := fx.New(
				fx.NopLogger,
				fx.Supply(configPath),
				internal.Module,
				decision.Module,
			)

			err := app.Err()
			if err != nil {
				cmd.PrintErrf("Failed to initialize decision service: %v", err)
				panic(err)
			}

			app.Run()
		},
	}
}
