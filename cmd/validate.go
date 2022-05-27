package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/validate"
)

// nolint: gochecknoglobals
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Commands for validating heimdall's configuration",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(cmd.UsageString())
	},
}

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(validateCmd)

	validateCmd.PersistentFlags().StringP("config", "c", "", "Config file")
	validateCmd.AddCommand(validate.NewValidateConfigCommand())
}
