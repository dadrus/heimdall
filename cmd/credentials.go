package cmd

import (
	"github.com/dadrus/heimdall/cmd/credentials"
	"github.com/spf13/cobra"
)

var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Generate RSA, ECDSA, and other keys and output them as JSON Web Keys",
}

func init() {
	RootCmd.AddCommand(credentialsCmd)

	credentialsCmd.AddCommand(credentials.NewGenerateCommand())
}
