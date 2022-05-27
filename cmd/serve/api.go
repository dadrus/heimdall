package serve

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/handler/decision"
)

// NewDecisionAPICommand represents the "serve api" command.
func NewDecisionAPICommand() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "Starts HTTP/2 Decision API Server",
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
				cmd.PrintErrf("Failed to initialize decision endpoint: %v", err)
				panic(err)
			}

			app.Run()
		},
	}
}
