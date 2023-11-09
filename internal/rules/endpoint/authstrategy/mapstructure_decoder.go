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

package authstrategy

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeAuthenticationStrategyHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var as endpoint.AuthenticationStrategy

		if from.Kind() != reflect.Map {
			return data, nil
		}

		dect := reflect.ValueOf(&as).Elem().Type()
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
		case "basic_auth":
			return decodeStrategy("basic_auth", &BasicAuth{}, typed["config"])
		case "api_key":
			return decodeStrategy("api_key", &APIKey{}, typed["config"])
		case "oauth2_client_credentials":
			return decodeStrategy("oauth2_client_credentials", &OAuth2ClientCredentials{}, typed["config"])
		default:
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"unsupported authentication type: '%s'", typed["type"])
		}
	}
}

func decodeStrategy[S endpoint.AuthenticationStrategy](
	name string,
	strategy S,
	config any,
) (endpoint.AuthenticationStrategy, error) {
	if config == nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"'%s' strategy requires 'config' property to be set", name)
	}

	if err := mapstructure.Decode(config, strategy); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to unmarshal '%s' strategy config", name).CausedBy(err)
	}

	if err := validation.ValidateStruct(strategy); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed validating '%s' strategy config", name).CausedBy(err)
	}

	return strategy, nil
}
