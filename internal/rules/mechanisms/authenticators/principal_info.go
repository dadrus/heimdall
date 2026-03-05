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

package authenticators

import (
	"github.com/tidwall/gjson"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type AttributeRefs map[string]string

type PrincipalInfo struct {
	IDFrom         string        `mapstructure:"id"         validate:"required"`
	AttributesFrom AttributeRefs `mapstructure:"attributes"`
}

func (s *PrincipalInfo) CreatePrincipal(rawData []byte) (*pipeline.Principal, error) {
	subjectID := gjson.GetBytes(rawData, s.IDFrom).String()
	if len(subjectID) == 0 {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"could not extract principal identifier using '%s' template", s.IDFrom)
	}

	principal := pipeline.Principal{
		ID: subjectID,
	}

	switch {
	case len(s.AttributesFrom) == 0:
		attrs, err := extractEntry(rawData, "@this", true)
		if err != nil {
			return nil, err
		}

		principal.Attributes = attrs.(map[string]any) //nolint: forcetypeassert
	case len(s.AttributesFrom) == 1:
		for key, value := range s.AttributesFrom {
			attrs, err := extractEntry(rawData, value, len(key) == 0)
			if err != nil {
				return nil, err
			}

			if len(key) == 0 {
				principal.Attributes = attrs.(map[string]any) //nolint: forcetypeassert
			} else {
				principal.Attributes = map[string]any{key: attrs}
			}

			break
		}
	default:
		principal.Attributes = make(map[string]any, len(s.AttributesFrom))
		for key, value := range s.AttributesFrom {
			attrs, err := extractEntry(rawData, value, false)
			if err != nil {
				return nil, err
			}

			principal.Attributes[key] = attrs
		}
	}

	return &principal, nil
}

func extractEntry(data []byte, path string, mapExpected bool) (any, error) {
	attributes := gjson.GetBytes(data, path).Value()
	if attributes == nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"could not extract attributes using '%s' template", path)
	}

	if mapExpected {
		_, ok := attributes.(map[string]any)
		if !ok {
			return nil, errorchain.NewWithMessage(pipeline.ErrInternal,
				"unexpected type of the extracted attribute(s)")
		}
	}

	return attributes, nil
}
