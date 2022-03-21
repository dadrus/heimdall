package health

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewReadyCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "ready",
		Short:   "Checks if an ORY Oathkeeper deployment is ready",
		Example: "oathkeeper health --endpoint=http://localhost:4456/ ready",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("health ready")
		},
	}
}
