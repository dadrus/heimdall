package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/rules"
)

// nolint
// rulesCmd represents the rules command.
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Commands for managing rules",
	Run: func(cmd *cobra.Command, args []string) {
		// nolint
		fmt.Println(cmd.UsageString())
	},
}

// nolint
func init() {
	RootCmd.AddCommand(rulesCmd)

	rulesCmd.PersistentFlags().StringP("endpoint", "e", "", "The endpoint URL of Heimdall's management API")
	rulesCmd.AddCommand(rules.NewGetCommand())
	rulesCmd.AddCommand(rules.NewListCommand())
}
