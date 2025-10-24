package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/convert"
)

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(newConvertCmd())
}

func newConvertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert",
		Short: "Commands for converting heimdall's resources between versions",
	}

	cmd.AddCommand(convert.NewConvertRulesCommand())

	return cmd
}
