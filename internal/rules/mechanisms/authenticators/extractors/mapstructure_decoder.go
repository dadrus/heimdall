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

package extractors

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeCompositeExtractStrategyHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var strategies CompositeExtractStrategy

		if from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&strategies).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// nolint: forcetypeassert
		// already checked above
		array := data.([]any)
		strategies = make(CompositeExtractStrategy, len(array))

		for idx, entry := range array {
			typed := map[string]string{}

			if values, ok := entry.(map[string]any); ok {
				for k, v := range values {
					// nolint: forcetypeassert
					// ok if panics
					typed[k] = v.(string)
				}
			} else if values, ok := entry.(map[any]any); ok {
				for k, v := range values {
					// nolint: forcetypeassert
					// ok if panics
					typed[k.(string)] = v.(string)
				}
			} else {
				return nil, errorchain.
					NewWithMessagef(heimdall.ErrInternal,
						"unexpected authentication config type %s", reflect.TypeOf(entry).String())
			}

			strategy, err := createStrategy(typed)
			if err != nil {
				return data, err
			}

			strategies[idx] = strategy
		}

		return strategies, nil
	}
}

func createStrategy(data map[string]string) (AuthDataExtractStrategy, error) {
	if value, ok := data["header"]; ok { // nolint: nestif
		var schema string
		if p, ok := data["schema"]; ok {
			schema = p
		}

		return &HeaderValueExtractStrategy{Name: value, Schema: schema}, nil
	} else if value, ok := data["cookie"]; ok {
		return &CookieValueExtractStrategy{Name: value}, nil
	} else if value, ok := data["query_parameter"]; ok {
		return &QueryParameterExtractStrategy{Name: value}, nil
	} else if value, ok := data["body_parameter"]; ok {
		return &BodyParameterExtractStrategy{Name: value}, nil
	}

	return nil, errorchain.
		NewWithMessage(heimdall.ErrConfiguration, "unsupported authentication source")
}
