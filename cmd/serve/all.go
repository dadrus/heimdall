package serve

import (
	"github.com/dadrus/heimdall/internal/decision"
	"github.com/dadrus/heimdall/internal/infrafx"
	"github.com/dadrus/heimdall/internal/proxy"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

// NewAllServicesCommand represents the proxy command
func NewAllServicesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "all",
		Short: "Starts both, the HTTP/2 Decision API Server, as well as the Reverse Proxy",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")

			app := fx.New(
				fx.Supply(configPath),
				infrafx.Module,
				decision.Module,
				proxy.Module,
			)

			if err := app.Err(); err == nil {
				app.Run()
			} else {
				panic(err)
			}
		},
	}
}
