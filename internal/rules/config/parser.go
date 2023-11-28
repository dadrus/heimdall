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
	"bytes"
	"errors"
	"io"

	"github.com/drone/envsubst/v2"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var ErrEmptyRuleSet = errors.New("empty rule set")

func ParseRules(contentType string, reader io.Reader, envUsageEnabled bool) (*RuleSet, error) {
	switch contentType {
	case "application/json":
		fallthrough
	case "application/yaml":
		return parseYAML(reader, envUsageEnabled)
	default:
		// check if the contents are empty. in that case nothing needs to be decoded anyway
		b := make([]byte, 1)
		if _, err := reader.Read(b); err != nil && errors.Is(err, io.EOF) {
			return nil, ErrEmptyRuleSet
		}

		// otherwise
		return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported '%s' content type", contentType)
	}
}

func parseYAML(reader io.Reader, envUsageEnabled bool) (*RuleSet, error) {
	var (
		rawConfig map[string]any
		ruleSet   RuleSet
	)

	if envUsageEnabled {
		raw, err := io.ReadAll(reader)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
				"failed to read rule set").CausedBy(err)
		}

		content, err := envsubst.EvalEnv(stringx.ToString(raw))
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"failed to evaluate env variables in rule set").CausedBy(err)
		}

		reader = bytes.NewReader(stringx.ToBytes(content))
	}

	dec := yaml.NewDecoder(reader)
	if err := dec.Decode(&rawConfig); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrEmptyRuleSet
		}

		return nil, err
	}

	if err := DecodeConfig(rawConfig, &ruleSet); err != nil {
		return nil, err
	}

	return &ruleSet, nil
}
