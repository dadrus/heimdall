package serve

import (
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/handler/proxy"
)

// NewProxyCommand represents the proxy command.
func NewProxyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "proxy",
		Short: "Starts HTTP/2 Reverse Proxy",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")

			app := fx.New(
				fx.Supply(configPath),
				internal.Module,
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
