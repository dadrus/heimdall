package rules

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewGetCommand creates the get command
func NewGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "get <id>",
		Short:   "Get access rule",
		Example: "oathkeeper rules --endpoint=http://localhost:4456/ get rule-1",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Calling endpoint")
		},
	}
}
