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

	"github.com/dadrus/heimdall/cmd/serve"
)

// nolint: gochecknoglobals
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Starts the heimdall in one of its operations modes (decision or proxy)",
}

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(serveCmd)

	serveCmd.PersistentFlags().StringP("config", "c", "",
		"Path to heimdall's configuration file.\n"+
			"If not provided, the lookup sequence is:\n  1. $PWD\n  2. $HOME/.config\n  3. /etc/heimdall/")
	serveCmd.PersistentFlags().String("env-config-prefix", "HEIMDALLCFG_",
		"Prefix for the environment variables to consider for\nloading configuration from")
	serveCmd.PersistentFlags().Bool("insecure", false,
		"Disables enforcement of all secure configurations entirely")
	serveCmd.PersistentFlags().Bool("insecure-no-ingress-tls", false,
		"Disables enforcement of TLS configuration for ingress traffic")
	serveCmd.PersistentFlags().Bool("insecure-no-egress-tls", false,
		"Disables enforcement of TLS configuration for egress traffic")
	serveCmd.PersistentFlags().Bool("insecure-default-rule", false,
		"Disables enforcement of secure configuration of the default rule")
	serveCmd.AddCommand(serve.NewProxyCommand())
	serveCmd.AddCommand(serve.NewDecisionCommand())
}
