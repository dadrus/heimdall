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
	"bytes"
	"os"

	"github.com/drone/envsubst/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func koanfFromYaml(configFile string, validateSyntax ConfigSyntaxValidator) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	raw, err := os.ReadFile(configFile)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to read yaml config from %s", configFile).CausedBy(err)
	}

	content, err := envsubst.EvalEnv(stringx.ToString(raw))
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to parse yaml config from %s", configFile).CausedBy(err)
	}

	rawContent := stringx.ToBytes(content)
	if err = validateSyntax(bytes.NewBuffer(rawContent)); err != nil {
		return nil, err
	}

	if err = parser.Load(rawbytes.Provider(rawContent), yaml.Parser()); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to load yaml config from %s", configFile).CausedBy(err)
	}

	return parser, nil
}
