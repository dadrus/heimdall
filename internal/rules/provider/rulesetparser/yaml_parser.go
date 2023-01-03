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

package rulesetparser

import (
	"errors"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/rules/rule"
)

func parseYAML(reader io.Reader) ([]rule.Configuration, error) {
	var (
		rawConfig []map[string]any
		rcs       []rule.Configuration
	)

	dec := yaml.NewDecoder(reader)
	if err := dec.Decode(&rawConfig); err != nil {
		if errors.Is(err, io.EOF) {
			return rcs, nil
		}

		return nil, err
	}

	err := rule.DecodeConfig(rawConfig, &rcs)

	return rcs, err
}
