package serve

import (
	"github.com/spf13/cobra"

	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/handler/decision"
	"github.com/dadrus/heimdall/internal/infrafx"
)

// NewDecisionApiCommand represents the proxy command
func NewDecisionApiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "Starts HTTP/2 Decision API Server",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")

			app := fx.New(
				fx.Supply(configPath),
				infrafx.Module,
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
