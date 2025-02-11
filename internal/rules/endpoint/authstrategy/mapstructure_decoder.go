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
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeAuthenticationStrategyHookFunc(ctx app.Context) mapstructure.DecodeHookFunc { //nolint:cyclop
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
			return decodeStrategy(ctx.Validator(), "basic_auth", &BasicAuth{}, typed["config"])
		case "api_key":
			return decodeStrategy(ctx.Validator(), "api_key", &APIKey{}, typed["config"])
		case "oauth2_client_credentials":
			strategy := &OAuth2ClientCredentials{}

			res, err := decodeStrategy(ctx.Validator(), "oauth2_client_credentials", strategy, typed["config"])
			if err != nil {
				return nil, err
			}

			if strings.HasPrefix(strategy.TokenURL, "http://") {
				logger := ctx.Logger()
				logger.Warn().Msg("No TLS configured for the oauth2_client_credentials strategy. " +
					"NEVER DO THIS IN PRODUCTION!!!")
			}

			return res, nil
		case "http_message_signatures":
			return decodeHTTPMessageSignaturesStrategy(ctx, typed["config"])
		default:
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"unsupported authentication type: '%s'", typed["type"])
		}
	}
}

func decodeHTTPMessageSignaturesStrategy(ctx app.Context, config any) (any, error) {
	httpSig := &HTTPMessageSignatures{}

	if _, err := decodeStrategy(ctx.Validator(), "http_message_signatures", httpSig, config); err != nil {
		return nil, err
	}

	if err := httpSig.init(); err != nil {
		return nil, err
	}

	if err := ctx.Watcher().Add(httpSig.Signer.KeyStore.Path, httpSig); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed registering http_message_signatures for updates").CausedBy(err)
	}

	ctx.CertificateObserver().Add(httpSig)

	return httpSig, nil
}

func decodeStrategy[S endpoint.AuthenticationStrategy](
	validator validation.Validator,
	name string,
	strategy S,
	config any,
) (endpoint.AuthenticationStrategy, error) {
	if config == nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"'%s' strategy requires 'config' property to be set", name)
	}

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
		),
		Result:      strategy,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to unmarshal '%s' strategy config", name).CausedBy(err)
	}

	if err = dec.Decode(config); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to unmarshal '%s' strategy config", name).CausedBy(err)
	}

	if err = validator.ValidateStruct(strategy); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed validating '%s' strategy config", name).CausedBy(err)
	}

	return strategy, nil
}
