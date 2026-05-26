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

package validate

import (
	"context"
	"errors"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/repository"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
	"github.com/dadrus/heimdall/internal/validation"
)

const validationForProxyMode = "proxy-mode"

var errFunctionNotSupported = errors.New("function not supported")

// NewValidateRulesCommand represents the "validate ruleset" command.
func NewValidateRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "ruleset [flags] [/path/to/ruleset.yaml]",
		Short:                 "Validates heimdall's ruleset",
		Args:                  cobra.ExactArgs(1),
		Example:               "heimdall validate ruleset -c myconfig.yaml myruleset.yaml",
		DisableFlagsInUseLine: true,
		SilenceErrors:         true,
		RunE:                  validateRuleSet,
	}

	cmd.Flags().Bool(validationForProxyMode, false,
		"If specified, validation considers usage in proxy operation mode")

	return cmd
}

//nolint:funlen
func validateRuleSet(cmd *cobra.Command, args []string) error {
	envPrefix, _ := cmd.Flags().GetString(flags.EnvironmentConfigPrefix)
	logger := zerolog.Nop()

	configPath, _ := cmd.Flags().GetString(flags.Config)
	if len(configPath) == 0 {
		return ErrNoConfigFile
	}

	cmd.SilenceUsage = true

	opMode := config.DecisionMode
	if proxyMode, _ := cmd.Flags().GetBool(validationForProxyMode); proxyMode {
		opMode = config.ProxyMode
	}

	es := flags.EnforcementSettings(cmd)

	validator, err := validation.NewValidator(
		validation.WithTagValidator(es),
		validation.WithErrorTranslator(es),
	)
	if err != nil {
		return err
	}

	df := encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct))

	conf, err := config.NewConfiguration(
		config.EnvVarPrefix(envPrefix),
		config.ConfigurationPath(configPath),
		validator,
	)
	if err != nil {
		return err
	}

	conf.Providers.FileSystem = map[string]any{"src": args[0]}

	appCtx := &appContext{
		kr: noopRegistry{},
		sr: noopResolver{},
		d:  df,
		l:  logger,
		c:  conf,
	}

	repo, err := repository.New(appCtx)
	if err != nil {
		return err
	}

	rFactory, err := rules.NewRuleFactory(
		repo,
		noopResolver{},
		conf,
		opMode,
		logger,
		nooptrace.Tracer{},
		noopmetric.Meter{},
		config.SecureDefaultRule(es.EnforceSecureDefaultRule),
	)
	if err != nil {
		return err
	}

	processor := rules.NewRuleSetProcessor(opMode, noopRepository{}, rFactory, noopScopedResolverFactory{})

	provider, err := filesystem.NewProvider(appCtx, processor)
	if err != nil {
		return err
	}

	if err = provider.Start(context.Background()); err != nil {
		return err
	}

	cmd.Println("Rule set is valid")

	return nil
}
