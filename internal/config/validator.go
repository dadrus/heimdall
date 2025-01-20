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
	"os"
	"strings"

	"github.com/knadh/koanf/maps"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
	"github.com/dadrus/heimdall/schema"
)

func ValidateConfigSchema(configPath string) error {
	contents, err := os.ReadFile(configPath)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"could not read config file").CausedBy(err)
	}

	if len(contents) == 0 {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration, "empty config file")
	}

	var conf map[string]any

	err = yaml.Unmarshal(contents, &conf)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to parse config file").CausedBy(err)
	}

	compiledSchema, err := compileSchema("config.schema.json", stringx.ToString(schema.ConfigSchema))
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to compile JSON schema").CausedBy(err)
	}

	maps.IntfaceKeysToStrings(conf)

	err = compiledSchema.Validate(conf)
	if err != nil {
		return errorchain.New(heimdall.ErrConfiguration).CausedBy(err)
	}

	return nil
}

func compileSchema(url, schemaContent string) (*jsonschema.Schema, error) {
	configSchema, err := jsonschema.UnmarshalJSON(strings.NewReader(schemaContent))
	if err != nil {
		return nil, err
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(url, configSchema); err != nil {
		return nil, err
	}

	return compiler.Compile(url)
}
