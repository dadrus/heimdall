package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version = "master"

	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:     "ngkeeper",
		Short:   "A cloud native Access and Identity Proxy",
		Version: Version,
	}
)

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
