package serve

import (
	"github.com/spf13/cobra"

	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/handler/proxy"
	"github.com/dadrus/heimdall/internal/infrafx"
)

// NewProxyCommand represents the proxy command
func NewProxyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "proxy",
		Short: "Starts HTTP/2 Reverse Proxy",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")

			app := fx.New(
				fx.Supply(configPath),
				infrafx.Module,
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
