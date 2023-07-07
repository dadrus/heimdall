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
	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/x/stringx"
)

type Matcher struct {
	URL      string `json:"url"      yaml:"url"`
	Strategy string `json:"strategy" yaml:"strategy"`
}

func (m *Matcher) UnmarshalJSON(data []byte) error {
	if data[0] == '"' {
		// data contains just the url matching value
		m.URL = stringx.ToString(data[1 : len(data)-1])
		m.Strategy = "glob"

		return nil
	}

	var rawData map[string]any

	if err := json.Unmarshal(data, &rawData); err != nil {
		return err
	}

	return DecodeConfig(rawData, m)
}
