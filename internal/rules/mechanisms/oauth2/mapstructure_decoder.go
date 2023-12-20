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

package oauth2

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeScopesMatcherHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var (
			matcher ScopesMatcher
			err     error
		)

		if from.Kind() != reflect.Map && from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&matcher).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// we care about these two cases only
		switch from.Kind() {
		case reflect.Map:
			matcher, err = decodeMatcherFromMap(data)
			if err != nil {
				return nil, err
			}
		case reflect.Slice:
			createMatcher := func(scopes []string) (ScopesMatcher, error) {
				return ExactScopeStrategyMatcher(scopes), nil
			}

			return createMatcherFromValues(createMatcher, data)
		default:
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "invalid structure for scopes matcher")
		}

		return matcher, nil
	}
}

type ScopeMatcherFactory func(scopes []string) (ScopesMatcher, error)

func decodeMatcherFromMap(data any) (ScopesMatcher, error) {
	var (
		createMatcher ScopeMatcherFactory
		err           error
	)

	typed := map[string]any{}

	if m, ok := data.(map[any]any); ok {
		// nolint: forcetypeassert
		// ok if panics
		for k, v := range m {
			typed[k.(string)] = v
		}
	} else if m, ok := data.(map[string]any); ok {
		typed = m
	} else {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "invalid structure for scopes matcher")
	}

	if name, ok := typed["matching_strategy"]; ok {
		createMatcher, err = matcherFactory(name.(string))
		if err != nil {
			return nil, err
		}
	} else {
		createMatcher = func(scopes []string) (ScopesMatcher, error) {
			return ExactScopeStrategyMatcher(scopes), nil
		}
	}

	if values, ok := typed["values"]; ok {
		return createMatcherFromValues(createMatcher, values)
	}

	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "invalid structure for scopes matcher")
}

func createMatcherFromValues(createMatcher ScopeMatcherFactory, values any) (ScopesMatcher, error) {
	scopes := make([]string, len(values.([]any))) // nolint: forcetypeassert
	for i, v := range values.([]any) {            // nolint: forcetypeassert
		scopes[i] = v.(string) // nolint: forcetypeassert
	}

	return createMatcher(scopes)
}

func matcherFactory(name string) (ScopeMatcherFactory, error) {
	switch name {
	case "exact":
		return func(scopes []string) (ScopesMatcher, error) {
			return ExactScopeStrategyMatcher(scopes), nil
		}, nil
	case "hierarchic":
		return func(scopes []string) (ScopesMatcher, error) {
			return HierarchicScopeStrategyMatcher(scopes), nil
		}, nil
	case "wildcard":
		return func(scopes []string) (ScopesMatcher, error) {
			return WildcardScopeStrategyMatcher(scopes), nil
		}, nil
	default:
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "unsupported strategy \"%s\"", name)
	}
}
