// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeAuthenticationDataForwardStrategy() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var strategy AuthDataForwardStrategy

		if from.Kind() != reflect.Map {
			return data, nil
		}

		dect := reflect.ValueOf(&strategy).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		typed := map[string]any{}

		if m, ok := data.(map[any]any); ok {
			for k, v := range m {
				// nolint: forcetypeassert
				// ok if panics
				typed[k.(string)] = v
			}
		} else if m, ok := data.(map[string]any); ok {
			typed = m
		} else {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "unexpected configuration type")
		}

		switch typed["type"] {
		case "body":
			return decodeForwardInBodyStrategy(typed["config"])
		case "query":
			return decodeForwardInQueryStrategy(typed["config"])
		case "cookie":
			return decodeForwardInCookieStrategy(typed["config"])
		case "header":
			return decodeForwardInHeadertrategy(typed["config"])
		default:
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"unsupported strategy type: '%s'", typed["type"])
		}
	}
}

func decodeForwardInBodyStrategy(config any) (AuthDataForwardStrategy, error) {
	var strategy BodyParameterForwardStrategy

	if config == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"body strategy requires 'config' property to be set")
	}

	err := mapstructure.Decode(config, &strategy)
	if err != nil {
		return nil, err
	}

	if len(strategy.Name) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"body strategy requires 'name' property to be set")
	}

	return &strategy, nil
}

func decodeForwardInQueryStrategy(config any) (AuthDataForwardStrategy, error) {
	var strategy QueryForwardStrategy

	if config == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"query strategy requires 'config' property to be set")
	}

	err := mapstructure.Decode(config, &strategy)
	if err != nil {
		return nil, err
	}

	if len(strategy.Name) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"query strategy requires 'name' property to be set")
	}

	return &strategy, nil
}

func decodeForwardInCookieStrategy(config any) (AuthDataForwardStrategy, error) {
	var strategy CookieForwardStrategy

	if config == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"cookie strategy requires 'config' property to be set")
	}

	err := mapstructure.Decode(config, &strategy)
	if err != nil {
		return nil, err
	}

	if len(strategy.Name) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"cookie strategy requires 'user' property to be set")
	}

	return &strategy, nil
}

func decodeForwardInHeadertrategy(config any) (AuthDataForwardStrategy, error) {
	var strategy HeaderForwardStrategy

	if config == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"header strategy requires 'config' property to be set")
	}

	err := mapstructure.Decode(config, &strategy)
	if err != nil {
		return nil, err
	}

	if len(strategy.Name) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"header strategy requires 'name' property to be set")
	}

	return &strategy, nil
}
