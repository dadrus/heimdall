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

package config

import (
	"fmt"
	"os"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/config/parser"
)

type Configuration struct {
	Serve   ServeConfig   `koanf:"serve"`
	Log     LoggingConfig `koanf:"log"`
	Tracing TracingConfig `koanf:"tracing"`
	Metrics MetricsConfig `koanf:"metrics"`
	Signer  SignerConfig  `koanf:"signer"`
	Cache   CacheConfig   `koanf:"cache"`
	Rules   Rules         `koanf:"rules,omitempty"`
}

func NewConfiguration(envPrefix EnvVarPrefix, configFile ConfigurationPath) (*Configuration, error) {
	// copy defaults
	result := defaultConfig

	opts := []parser.Option{
		parser.WithDecodeHookFunc(mapstructure.StringToTimeDurationHookFunc()),
		parser.WithDecodeHookFunc(mapstructure.StringToSliceHookFunc(",")),
		parser.WithDecodeHookFunc(logLevelDecodeHookFunc),
		parser.WithDecodeHookFunc(logFormatDecodeHookFunc),
		parser.WithDecodeHookFunc(decodeTLSCipherSuiteHookFunc),
		parser.WithDecodeHookFunc(decodeTLSMinVersionHookFunc),
		parser.WithEnvPrefix(string(envPrefix)),
		parser.WithDefaultConfigFilename("heimdall.yaml"),
		parser.WithConfigFile(string(configFile)),
		parser.WithConfigValidator(ValidateConfig),
	}

	// if no config file provided, the lookup order for the heimdall.yaml file is:
	//
	// 1. current working directory
	// 2. $HOME/.config
	// 3. /etc/heimdall/
	pwd, err := os.Getwd()
	if err == nil {
		opts = append(opts, parser.WithConfigLookupDir(pwd))
	}

	homeDir, err := os.UserHomeDir()
	if err == nil {
		opts = append(opts, parser.WithConfigLookupDir(fmt.Sprintf("%s/.config/", homeDir)))
	}

	opts = append(opts, parser.WithConfigLookupDir("/etc/heimdall/"))

	err = parser.New(opts...).Load(&result)

	return &result, err
}
