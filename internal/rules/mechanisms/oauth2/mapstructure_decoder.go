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

	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/pipeline"
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

		switch from.Kind() { //nolint:exhaustive
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
		}

		return matcher, nil
	}
}

type scopeMatcherFactory func(scopes []string) (ScopesMatcher, error)

type scopePatternSource string

const (
	scopePatternSourceGranted  scopePatternSource = "granted"
	scopePatternSourceRequired scopePatternSource = "required"
)

func decodeMatcherFromMap(data any) (ScopesMatcher, error) {
	typed, err := asStringMap(data)
	if err != nil {
		return nil, err
	}

	createMatcher, err := scopeMatcherFactoryFromConfig(typed)
	if err != nil {
		return nil, err
	}

	match, err := scopeListMatchFromConfig(typed)
	if err != nil {
		return nil, err
	}

	values, ok := typed["values"]
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"invalid structure for scopes matcher",
		)
	}

	scopes, err := scopesFromValues(values)
	if err != nil {
		return nil, err
	}

	return createListMatcher(match, scopes, createMatcher)
}

func scopeMatcherFactoryFromConfig(typed map[string]any) (scopeMatcherFactory, error) {
	createMatcher := func(scopes []string) (ScopesMatcher, error) {
		return ExactScopeStrategyMatcher(scopes), nil
	}

	rawStrategy, ok := typed["matching_strategy"]
	if !ok {
		if _, ok := typed["pattern_source"]; ok {
			return nil, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"scope pattern source is only supported with wildcard matching strategy",
			)
		}

		return createMatcher, nil
	}

	strategy, ok := rawStrategy.(string)
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"invalid matching strategy type",
		)
	}

	patternSource, err := scopePatternSourceFromConfig(typed)
	if err != nil {
		return nil, err
	}

	return matcherFactory(strategy, patternSource)
}

func scopePatternSourceFromConfig(typed map[string]any) (scopePatternSource, error) {
	raw, ok := typed["pattern_source"]
	if !ok {
		return "", nil
	}

	source, ok := raw.(string)
	if !ok {
		return "", errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"invalid scope pattern source type",
		)
	}

	switch source {
	case string(scopePatternSourceGranted):
		return scopePatternSourceGranted, nil
	case string(scopePatternSourceRequired):
		return scopePatternSourceRequired, nil
	default:
		return "", errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"unsupported scope pattern source \"%s\"",
			source,
		)
	}
}

func scopeListMatchFromConfig(typed map[string]any) (string, error) {
	raw, ok := typed["match"]
	if !ok {
		return "all", nil
	}

	match, ok := raw.(string)
	if !ok {
		return "", errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"invalid scope match type",
		)
	}

	return match, nil
}

func createListMatcher(match string, scopes []string, createMatcher scopeMatcherFactory) (ScopesMatcher, error) {
	switch match {
	case "all":
		return createMatcher(scopes)
	case "any":
		matcher, err := NewAnyScopeMatcher(scopes, createMatcher)
		if err != nil {
			return nil, err
		}

		return matcher, nil
	default:
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration, "unsupported scope match \"%s\"", match)
	}
}

func createMatcherFromValues(createMatcher scopeMatcherFactory, values any) (ScopesMatcher, error) {
	scopes, err := scopesFromValues(values)
	if err != nil {
		return nil, err
	}

	return createMatcher(scopes)
}

func scopesFromValues(values any) ([]string, error) {
	raw, ok := values.([]any)
	if !ok {
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"invalid scope values",
		)
	}

	scopes := make([]string, len(raw))
	for i, value := range raw {
		scope, ok := value.(string)
		if !ok {
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"invalid scope value '%v'", value,
			)
		}

		scopes[i] = scope
	}

	return scopes, nil
}

func matcherFactory(name string, patternSource scopePatternSource) (scopeMatcherFactory, error) {
	switch name {
	case "exact":
		if patternSource != "" {
			return nil, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"scope pattern source is only supported with wildcard matching strategy",
			)
		}

		return func(scopes []string) (ScopesMatcher, error) {
			return ExactScopeStrategyMatcher(scopes), nil
		}, nil
	case "hierarchic":
		if patternSource != "" {
			return nil, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"scope pattern source is only supported with wildcard matching strategy",
			)
		}

		return func(scopes []string) (ScopesMatcher, error) {
			return HierarchicScopeStrategyMatcher(scopes), nil
		}, nil
	case "wildcard":
		if patternSource == "" {
			patternSource = scopePatternSourceGranted
		}

		switch patternSource {
		case scopePatternSourceGranted:
			return func(scopes []string) (ScopesMatcher, error) {
				return WildcardScopeStrategyMatcher(scopes), nil
			}, nil
		case scopePatternSourceRequired:
			return func(scopes []string) (ScopesMatcher, error) {
				return RequiredWildcardScopeStrategyMatcher(scopes), nil
			}, nil
		}
	default:
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration, "unsupported strategy \"%s\"", name)
	}

	return nil, errorchain.NewWithMessagef(
		pipeline.ErrConfiguration,
		"unsupported scope pattern source \"%s\"",
		patternSource,
	)
}

func DecodePoPStrategyHookFunc(ctx app.Context) mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.Map {
			return data, nil
		}

		if !reflect.TypeFor[*PoPStrategy]().Elem().AssignableTo(to) {
			return data, nil
		}

		raw, err := asStringMap(data)
		if err != nil {
			return nil, err
		}

		typ, _ := raw["type"].(string)

		conf, err := asStringMap(raw["config"])
		if err != nil {
			return nil, err
		}

		switch PoPType(typ) {
		case DPoP:
			return newDPoPStrategy(ctx, conf)
		case MTLS:
			return &mtlsPoPStrategy{}, nil
		default:
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"unsupported proof_of_possession type \"%s\"", typ)
		}
	}
}

func asStringMap(data any) (map[string]any, error) {
	if data == nil {
		return map[string]any{}, nil
	}

	switch typed := data.(type) {
	case map[string]any:
		return typed, nil
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, value := range typed {
			strKey, ok := key.(string)
			if !ok {
				return nil, errorchain.NewWithMessage(
					pipeline.ErrConfiguration,
					"configuration contains non-string key",
				)
			}

			result[strKey] = value
		}

		return result, nil
	default:
		return nil, errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"unexpected configuration type",
		)
	}
}
