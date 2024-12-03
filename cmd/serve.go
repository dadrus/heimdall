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

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/cmd/serve"
)

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(newServeCmd())
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Starts the heimdall in one of its operations modes (decision or proxy)",
	}

	cmd.PersistentFlags().StringP(flags.Config, "c", "",
		"Path to heimdall's configuration file.\n"+
			"If not provided, the lookup sequence is:\n  1. $PWD\n  2. $HOME/.config\n  3. /etc/heimdall/")
	cmd.PersistentFlags().String(flags.EnvironmentConfigPrefix, "HEIMDALLCFG_",
		"Prefix for the environment variables to consider for\nloading configuration from")
	cmd.PersistentFlags().Bool(flags.SkipAllSecurityEnforcement, false,
		"Disables enforcement of all secure configurations entirely.\n"+
			"Effectively it enables all the --skip-*-enforcement flags below.")
	cmd.PersistentFlags().Bool(flags.SkipAllTLSEnforcement, false,
		"Disables enforcement of TLS for every in- and outbound connection.\n"+
			"Effectively it enables all the --skip-*-tls-enforcement flags.")
	cmd.PersistentFlags().Bool(flags.SkipIngressTLSEnforcement, false,
		"Disables enforcement of TLS configuration for ingress traffic.")
	cmd.PersistentFlags().Bool(flags.SkipEgressTLSEnforcement, false,
		"Disables enforcement of TLS configuration for egress traffic.")
	cmd.PersistentFlags().Bool(flags.SkipUpstreamTLSEnforcement, false,
		"Disables enforcement of TLS while proxying the requests to the\nupstream services.")
	cmd.PersistentFlags().Bool(flags.SkipSecureDefaultRuleEnforcement, false,
		"Disables enforcement of secure configuration of the default\nrule.")

	cmd.AddCommand(serve.NewProxyCommand())
	cmd.AddCommand(serve.NewDecisionCommand())

	return cmd
}
