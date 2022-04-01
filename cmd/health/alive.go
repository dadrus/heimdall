package health

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewAliveCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "alive",
		Short:   "Checks if an Heimdall deployment is alive",
		Example: "heimdall health --endpoint=http://localhost:4456/ alive",
		Run: func(cmd *cobra.Command, args []string) {
			// nolint
			fmt.Println("health alive")
		},
	}
}
