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
	"net/http"
	"reflect"

	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type authStrategy interface {
	init(appCtx app.Context) error
	Apply(req *http.Request) error
	Hash() []byte
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
		return err
	}

	dec := decoderFactory.Decoder(
		encoding.WithTagName("mapstructure"),
		encoding.WithDecodeHooks(
			mapstructure.StringToTimeDurationHookFunc(),
		),
		encoding.WithErrorOnUnused(true),
	)

	return dec.DecodeMap(out, typed)
}

func DecodeAuthenticationStrategyHookFunc(appCtx app.Context) mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.Map {
			return data, nil
		}

		if !reflect.TypeFor[*endpoint.AuthenticationStrategy]().Elem().AssignableTo(to) {
			return data, nil
		}

		raw := data.(map[string]any) //nolint: forcetypeassert
		typ, _ := raw["type"].(string)

		var strategy authStrategy

		switch typ {
		case "basic_auth":
			strategy = &BasicAuth{}
		case "api_key":
			strategy = &APIKey{}
		case "oauth2_client_credentials":
			strategy = &OAuth2ClientCredentials{}
		case "http_message_signatures":
			strategy = &HTTPMessageSignatures{}
		default:
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"unsupported authentication type: '%s'",
				typ,
			)
		}

		if err := decodeConfig(appCtx.DecoderFactory(), typ, strategy, raw["config"]); err != nil {
			return nil, errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"failed to unmarshal '%s' strategy config",
				typ,
			).CausedBy(err)
		}

		if err := strategy.init(appCtx); err != nil {
			return nil, err
		}

		return strategy, nil
	}
}
