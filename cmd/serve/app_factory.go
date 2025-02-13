// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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
	"bytes"
	"slices"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/logging"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/version"
)

func createApp(cmd *cobra.Command, mainModule fx.Option) (*fx.App, error) {
	configPath, _ := cmd.Flags().GetString(flags.Config)
	envPrefix, _ := cmd.Flags().GetString(flags.EnvironmentConfigPrefix)
	cli := bytes.NewBufferString(cmd.CommandPath())
	es := flags.EnforcementSettings(cmd)
	securityEnforcementDisabled := false

	cmd.Flags().Visit(func(flag *pflag.Flag) {
		cli.WriteString(" --")
		cli.WriteString(flag.Name)

		if flag.Value.Type() != "bool" {
			cli.WriteString(" ")
			cli.WriteString(flag.Value.String())
		}

		if slices.Contains(flags.InsecureFlags, flag.Name) {
			securityEnforcementDisabled = true
		}
	})

	validator, err := validation.NewValidator(
		validation.WithTagValidator(es),
		validation.WithErrorTranslator(es),
	)
	if err != nil {
		return nil, err
	}

	cfg, err := config.NewConfiguration(
		config.EnvVarPrefix(envPrefix),
		config.ConfigurationPath(configPath),
		validator,
	)
	if err != nil {
		return nil, err
	}

	logger := logging.NewLogger(cfg.Log)
	logger.Info().
		Str("_version", version.Version).
		Str("_cli", cli.String()).
		Msg("Starting heimdall")

	if securityEnforcementDisabled {
		logger.Warn().Msg("Enforcement of secure settings disabled")
	}

	app := fx.New(
		fx.Supply(
			cfg,
			logger,
			config.SecureDefaultRule(es.EnforceSecureDefaultRule),
			fx.Annotate(validator, fx.As(new(validation.Validator))),
		),
		fx.WithLogger(func(logger zerolog.Logger) fxevent.Logger {
			return &eventLogger{l: logger}
		}),
		internal.Module,
		mainModule,
	)

	return app, app.Err()
}
