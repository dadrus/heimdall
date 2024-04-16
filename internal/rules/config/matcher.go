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
	"slices"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type Path struct {
	Expression string `json:"expression" yaml:"expression" validate:"required"` //nolint:tagalign
	Glob       string `json:"glob"       yaml:"glob"`
	Regex      string `json:"regex"      yaml:"regex"`
}

func (p *Path) UnmarshalJSON(data []byte) error {
	if data[0] == '"' {
		// data contains just the path expression
		p.Expression = stringx.ToString(data[1 : len(data)-1])

		return nil
	}

	var rawData map[string]any

	if err := json.Unmarshal(data, &rawData); err != nil {
		return err
	}

	return DecodeConfig(rawData, p)
}

type Matcher struct {
	Scheme    string   `json:"scheme"     yaml:"scheme"`
	Methods   []string `json:"methods"    yaml:"methods"`
	HostGlob  string   `json:"host_glob"  yaml:"host_glob"`
	HostRegex string   `json:"host_regex" yaml:"host_regex"`
	Path      Path     `json:"path"       yaml:"path"`
}

func (m *Matcher) DeepCopyInto(out *Matcher) {
	*out = *m
	out.Methods = slices.Clone(m.Methods)
}
