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
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal/cache"
	_ "github.com/dadrus/heimdall/internal/cache/module" // without this import, available cache configs are not registered.
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/rules/provider/cloudblob"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
	"github.com/dadrus/heimdall/internal/rules/provider/httpendpoint"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/watcher"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// NewValidateConfigCommand represents the "validate config" command.
func NewValidateConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "config",
		Short:        "Validates heimdall's configuration",
		Example:      "heimdall validate config -c myconfig.yaml",
		SilenceUsage: true,
		RunE:         validateConfig,
	}
}

func validateConfig(cmd *cobra.Command, _ []string) error {
	envPrefix, _ := cmd.Flags().GetString(flags.EnvironmentConfigPrefix)
	configPath, _ := cmd.Flags().GetString(flags.Config)
	logger := zerolog.Nop()

	if len(configPath) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "no config file provided")
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
		config.DecisionMode,
		logger,
		config.SecureDefaultRule(es.EnforceSecureDefaultRule),
	)
	if err != nil {
		return err
	}

	cch, err := cache.Create(appCtx, conf.Cache.Type, conf.Cache.Config)
	if err != nil {
		return err
	}

	rProcessor := rules.NewRuleSetProcessor(&noopRepository{}, rFactory, config.DecisionMode)

	_, err = filesystem.NewProvider(appCtx, rProcessor)
	if err != nil {
		return err
	}

	_, err = cloudblob.NewProvider(appCtx, rProcessor)
	if err != nil {
		return err
	}

	_, err = httpendpoint.NewProvider(appCtx, rProcessor, cch)
	if err != nil {
		return err
	}

	// ignoring kubernetes provider for now as there are no insecure
	// settings possible

	cmd.Println("Configuration is valid")

	return nil
}
