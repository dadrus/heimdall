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

package parser

import (
	"io"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

type ConfigSyntaxValidator func(cfgSrc io.Reader) error

type ConfigSemanticsValidator func(cfg any) error

type opts struct {
	configFile            string
	defaultConfigFileName string
	configLookupDirs      []string
	decodeHooks           []mapstructure.DecodeHookFunc
	validateSyntax        ConfigSyntaxValidator
	validateSemantics     ConfigSemanticsValidator
	envPrefix             string
}

type Option func(*opts)

func WithConfigFile(file string) Option {
	return func(o *opts) {
		configFile := strings.TrimSpace(file)
		if len(configFile) != 0 {
			o.configFile = configFile
		}
	}
}

func WithDefaultConfigFilename(name string) Option {
	return func(o *opts) {
		fileName := strings.TrimSpace(name)
		if len(fileName) != 0 {
			o.defaultConfigFileName = fileName
		}
	}
}

func WithDecodeHookFunc(hook mapstructure.DecodeHookFunc) Option {
	return func(o *opts) {
		if hook != nil {
			o.decodeHooks = append(o.decodeHooks, hook)
		}
	}
}

func WithConfigLookupDir(file string) Option {
	return func(o *opts) {
		dir := strings.TrimSpace(file)
		if len(dir) != 0 {
			o.configLookupDirs = append(o.configLookupDirs, dir)
		}
	}
}

func WithConfigSyntaxValidator(validator ConfigSyntaxValidator) Option {
	return func(o *opts) {
		if validator != nil {
			o.validateSyntax = validator
		}
	}
}

func WithConfigSemanticsValidator(validator ConfigSemanticsValidator) Option {
	return func(o *opts) {
		if validator != nil {
			o.validateSemantics = validator
		}
	}
}

func WithEnvPrefix(prefix string) Option {
	return func(o *opts) {
		prefix = strings.TrimSpace(prefix)
		if len(prefix) != 0 {
			o.envPrefix = prefix
		}
	}
}
