package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/credentials"
)

// nolint
var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Generate RSA, ECDSA, and other keys and output them as JSON Web Keys",
}

// nolint
func init() {
	RootCmd.AddCommand(credentialsCmd)

	credentialsCmd.AddCommand(credentials.NewGenerateCommand())
}
