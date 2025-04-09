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
	"fmt"
	"os"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ConfigLoader interface {
	Load(config any) error
}

func New(opts ...Option) ConfigLoader {
	loader := &configLoader{o: defaultOptions}

	for _, opt := range opts {
		opt(&loader.o)
	}

	return loader
}

type configLoader struct {
	o opts
}

func (c *configLoader) Load(config any) error {
	configFile, err := c.configFile()
	if err != nil {
		return err
	}

	parser, err := koanfFromStruct(config)
	if err != nil {
		return err
	}

	if len(configFile) != 0 {
		if err = c.loadAndMergeConfig(parser, func() (*koanf.Koanf, error) {
			return koanfFromYaml(configFile, c.o.validateSyntax)
		}); err != nil {
			return err
		}
	}

	if err = c.loadAndMergeConfig(parser, func() (*koanf.Koanf, error) {
		return koanfFromEnv(c.o.envPrefix)
	}); err != nil {
		return err
	}

	if err = parser.UnmarshalWithConf("", config, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.ComposeDecodeHookFunc(c.o.decodeHooks...),
			Metadata:         nil,
			Result:           config,
			WeaklyTypedInput: true,
		},
	}); err != nil {
		return err
	}

	return c.validateSemantics(config)
}

func (c *configLoader) configFile() (string, error) {
	if len(c.o.configFile) != 0 {
		_, err := os.Stat(c.o.configFile)
		if err != nil {
			return "", errorchain.New(heimdall.ErrConfiguration).CausedBy(err)
		}

		return c.o.configFile, nil
	}

	for _, confDir := range c.o.configLookupDirs {
		filePath := fmt.Sprintf("%s/%s", confDir, c.o.defaultConfigFileName)
		if _, err := os.Stat(filePath); err == nil {
			return filePath, nil
		}
	}

	return "", nil
}

func (c *configLoader) loadAndMergeConfig(parser *koanf.Koanf, loadConfig func() (*koanf.Koanf, error)) error {
	konf, err := loadConfig()
	if err != nil {
		return err
	}

	err = parser.Load(
		confmap.Provider(konf.Raw(), ""),
		nil,
		koanf.WithMergeFunc(func(src, dest map[string]any) error {
			for key, val := range src {
				dest[key] = merge(dest[key], val)
			}

			return nil
		}))
	if err != nil {
		return errorchain.New(heimdall.ErrConfiguration).CausedBy(err)
	}

	return nil
}

func (c *configLoader) validateSemantics(config any) error {
	if err := c.o.validateSemantics(config); err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "configuration is invalid").CausedBy(err)
	}

	return nil
}
