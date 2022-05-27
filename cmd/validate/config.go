package validate

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/config"
)

var ErrNoConfigFile = errors.New("no config file provided")

// NewValidateConfigCommand represents the "validate config" command.
func NewValidateConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Validates heimdall's configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, _ := cmd.Flags().GetString("config")
			if len(configPath) == 0 {
				return ErrNoConfigFile
			}

			if err := config.ValidateConfig(configPath); err != nil {
				cmd.PrintErrf("%v\n", err)
			}

			cmd.Printf("Configuration is valid\n")

			return nil
		},
	}
}
