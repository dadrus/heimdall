package credentials

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewGenerateCommand represents the generate command
func NewGenerateCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "generate",
		Short:   "Generate a key for the specified algorithm",
		Example: "heimdall credentials generate --alg RS256 --bits 4096 > jwks.json",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("generating keys")
		},
	}

	cmd.Flags().String("alg", "", fmt.Sprintf("Generate a key to be used for one of the following algorithms: %v",
		"RS256 ..."))
	cmd.Flags().String("kid", "", "The JSON Web Key ID (kid) to be used. A random value will be used if left empty.")
	cmd.Flags().Int("bits", 0, "The key size in bits. If left empty will default to a secure value for the selected algorithm.")

	if err := cmd.MarkFlagRequired("alg"); err != nil {
		panic(err)
	}

	return cmd
}
