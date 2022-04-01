package serve

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/handler/decision"
)

// NewDecisionAPICommand represents the proxy command.
func NewDecisionAPICommand() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "Starts HTTP/2 Decision API Server",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")

			app := fx.New(
				fx.Supply(configPath),
				internal.Module,
				decision.Module,
			)

			if err := app.Err(); err == nil {
				app.Run()
			} else {
				panic(err)
			}
		},
	}
}
