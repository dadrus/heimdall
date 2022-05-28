package serve

import (
	"os"

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
			cmd.PrintErrf("Not yet supported")

			os.Exit(-1)

			configPath, _ := cmd.Flags().GetString("config")

			app := fx.New(
				fx.NopLogger,
				fx.Supply(configPath),
				internal.Module,
				proxy.Module,
			)

			err := app.Err()
			if err != nil {
				cmd.PrintErrf("Failed to initialize proxy endpoint: %v", err)
				panic(err)
			}

			app.Run()
		},
	}
}
