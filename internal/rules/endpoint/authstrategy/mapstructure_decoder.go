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
	"context"
	"errors"
	"reflect"

	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type initializableStrategy interface {
	init(context.Context, app.Context) error
}

var authStrategyTypes = map[string]func() endpoint.AuthenticationStrategy{
	"basic_auth":                func() endpoint.AuthenticationStrategy { return &BasicAuth{} },
	"api_key":                   func() endpoint.AuthenticationStrategy { return &APIKey{} },
	"oauth2_client_credentials": func() endpoint.AuthenticationStrategy { return &OAuth2ClientCredentials{} },
	"http_message_signatures":   func() endpoint.AuthenticationStrategy { return &HTTPMessageSignatures{} },
}

func asStringMap(data any) (map[string]any, error) {
	switch typed := data.(type) {
	case map[string]any:
		return typed, nil
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, value := range typed {
			strKey, ok := key.(string)
			if !ok {
				return nil, errors.New("configuration contains non-string key")
			}

			result[strKey] = value
		}

		return result, nil
	default:
		return nil, errors.New("unexpected configuration type")
	}
}

func decodeConfig(
	decoderFactory encoding.DecoderFactory,
	name string,
	out any,
	config any,
) error {
	if config == nil {
		return errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"'%s' strategy requires 'config' property to be set",
			name,
		)
	}

	typed, err := asStringMap(config)
	if err != nil {
		return errorchain.NewWithMessage(
			pipeline.ErrConfiguration,
			"unexpected configuration type",
		).CausedBy(err)
	}

	dec := decoderFactory.Decoder(
		encoding.WithTagName("mapstructure"),
		encoding.WithDecodeHooks(
			mapstructure.StringToTimeDurationHookFunc(),
		),
		encoding.WithErrorOnUnused(true),
	)

	if err := dec.DecodeMap(out, typed); err != nil {
		return errorchain.NewWithMessagef(
			pipeline.ErrConfiguration,
			"failed to unmarshal '%s' strategy config",
			name,
		).CausedBy(err)
	}

	return nil
}

func DecodeAuthenticationStrategyHookFunc(appCtx app.Context) mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.Map {
			return data, nil
		}

		if !reflect.TypeOf((*endpoint.AuthenticationStrategy)(nil)).Elem().AssignableTo(to) {
			return data, nil
		}

		raw, ok := data.(map[string]any)
		if !ok {
			return nil, errorchain.NewWithMessage(
				pipeline.ErrConfiguration,
				"unexpected authentication strategy configuration type",
			)
		}

		typ, _ := raw["type"].(string)

		factory, ok := authStrategyTypes[typ]
		if !ok {
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"unsupported authentication type: '%s'",
				typ,
			)
		}

		strategy := factory()

		if err := decodeConfig(appCtx.DecoderFactory(), typ, strategy, raw["config"]); err != nil {
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"failed to unmarshal '%s' strategy config",
				typ,
			).CausedBy(err)
		}

		if initable, ok := strategy.(initializableStrategy); ok {
			if err := initable.init(context.Background(), appCtx); err != nil {
				return nil, err
			}
		}

		return strategy, nil
	}
}
