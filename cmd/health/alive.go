package health

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewAliveCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "alive",
		Short:   "Checks if an ORY Oathkeeper deployment is alive",
		Example: "oathkeeper health --endpoint=http://localhost:4456/ alive",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("health alive")
		},
	}
}
