// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package serve

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/proxy"
	"github.com/dadrus/heimdall/internal/validation"
)

// NewProxyCommand represents the proxy command.
func NewProxyCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "proxy",
		Short:   "Starts heimdall in Reverse Proxy operation mode",
		Example: "heimdall serve proxy",
		Run: func(cmd *cobra.Command, _ []string) {
			app, err := createProxyApp(cmd)
			if err != nil {
				cmd.PrintErrf("Failed to initialize proxy service: %v", err)

				os.Exit(1)
			}

			app.Run()
		},
	}
}

func createProxyApp(cmd *cobra.Command) (*fx.App, error) {
	configPath, _ := cmd.Flags().GetString(flags.Config)
	envPrefix, _ := cmd.Flags().GetString(flags.EnvironmentConfigPrefix)
	es := flags.EnforcementSettings(cmd)

	validator, err := validation.NewValidator(
		validation.WithTagValidator(es),
		validation.WithErrorTranslator(es),
	)
	if err != nil {
		return nil, err
	}

	app := fx.New(
		fx.NopLogger,
		fx.Supply(
			config.ConfigurationPath(configPath),
			config.EnvVarPrefix(envPrefix),
			config.SecureDefaultRule(es.EnforceSecureDefaultRule),
			config.ProxyMode,
			fx.Annotate(validator, fx.As(new(validation.Validator))),
		),
		internal.Module,
		proxy.Module,
	)

	return app, app.Err()
}
