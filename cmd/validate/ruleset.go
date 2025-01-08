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
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/keyholder"
	"github.com/dadrus/heimdall/internal/otel/metrics/certificate"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher"
)

var errFunctionNotSupported = errors.New("function not supported")

// NewValidateRulesCommand represents the "validate rules" command.
func NewValidateRulesCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "rules [path to ruleset]",
		Short:   "Validates heimdall's ruleset",
		Args:    cobra.ExactArgs(1),
		Example: "heimdall validate rules -c myconfig.yaml myruleset.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			if err := validateRuleSet(cmd, args); err != nil {
				cmd.PrintErrf("%v\n", err)

				os.Exit(1)
			}

			cmd.Println("Rule set is valid")
		},
	}
}

func validateRuleSet(cmd *cobra.Command, args []string) error {
	envPrefix, _ := cmd.Flags().GetString(flags.EnvironmentConfigPrefix)
	logger := zerolog.Nop()

	configPath, _ := cmd.Flags().GetString(flags.Config)
	if len(configPath) == 0 {
		return ErrNoConfigFile
	}

	opMode := config.DecisionMode
	if proxyMode, _ := cmd.Flags().GetBool(flags.ValidationInProxyMode); proxyMode {
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
		w:   &watcher.NoopWatcher{},
		khr: &noopRegistry{},
		co:  &noopCertificateObserver{},
		v:   validator,
		l:   logger,
		c:   conf,
	}

	mFactory, err := mechanisms.NewMechanismFactory(appCtx)
	if err != nil {
		return err
	}

	rFactory, err := rules.NewRuleFactory(
		mFactory,
		conf,
		opMode,
		logger,
		config.SecureDefaultRule(es.EnforceSecureDefaultRule),
	)
	if err != nil {
		return err
	}

	provider, err := filesystem.NewProvider(appCtx, rules.NewRuleSetProcessor(&noopRepository{}, rFactory))
	if err != nil {
		return err
	}

	return provider.Start(context.Background())
}

type noopRepository struct{}

func (*noopRepository) FindRule(_ heimdall.Context) (rule.Rule, error) {
	return nil, errFunctionNotSupported
}
func (*noopRepository) AddRuleSet(_ string, _ []rule.Rule) error    { return nil }
func (*noopRepository) UpdateRuleSet(_ string, _ []rule.Rule) error { return errFunctionNotSupported }
func (*noopRepository) DeleteRuleSet(_ string) error                { return errFunctionNotSupported }

type noopRegistry struct{}

func (*noopRegistry) AddKeyHolder(_ keyholder.KeyHolder) {}
func (*noopRegistry) Keys() []jose.JSONWebKey            { return nil }

type noopCertificateObserver struct{}

func (*noopCertificateObserver) Add(_ certificate.Supplier) {}
func (*noopCertificateObserver) Start() error               { return errFunctionNotSupported }
