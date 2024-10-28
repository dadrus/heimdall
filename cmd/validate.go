// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/validate"
)

// nolint: gochecknoglobals
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Commands for validating heimdall's configuration",
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.Println(cmd.UsageString())
	},
}

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(validateCmd)

	validateCmd.PersistentFlags().StringP("config", "c", "",
		"Path to heimdall's configuration file.")
	validateCmd.PersistentFlags().String("env-config-prefix", "HEIMDALLCFG_",
		"Prefix for the environment variables to consider for\nloading configuration from")
	validateCmd.PersistentFlags().Bool("insecure", false,
		"Disables enforcement of all secure configurations entirely")
	validateCmd.PersistentFlags().Bool("insecure-no-ingress-tls", false,
		"Disables enforcement of TLS configuration for ingress traffic")
	validateCmd.PersistentFlags().Bool("insecure-no-egress-tls", false,
		"Disables enforcement of TLS configuration for egress traffic")
	validateCmd.PersistentFlags().Bool("insecure-default-rule", false,
		"Disables enforcement of secure configuration of the default rule")

	validateCmd.AddCommand(validate.NewValidateConfigCommand())
	validateCmd.AddCommand(validate.NewValidateRulesCommand())
}
