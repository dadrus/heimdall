package rules

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewListCommand represents the list command.
func NewListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List access rules",
		Example: "heimdall rules --endpoint=http://localhost:4456/ list",
		Run: func(cmd *cobra.Command, args []string) {
			// nolint
			fmt.Println("calling rules ep")
		},
	}

	cmd.Flags().Int("limit", 20, "The maximum amount of policies returned.")
	cmd.Flags().Int("page", 1, "The number of page.")

	return cmd
}
