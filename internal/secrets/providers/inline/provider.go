// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package inline

import (
	"context"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const ProviderType = "inline"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(ProviderType, registry.FactoryFunc(newProvider))
}

type provider struct {
	name        string
	secrets     map[string]types.Secret
	credentials map[string]types.Credentials
}

func newProvider(_ app.Context, sourceName string, rawConf map[string]any) (types.Provider, error) {
	if len(rawConf) == 0 {
		return nil, errorchain.NewWithMessage(types.ErrInvalidSecretPayload,
			"inline provider config must not be empty")
	}

	secrets := make(map[string]types.Secret, len(rawConf))
	credentials := make(map[string]types.Credentials, len(rawConf))

	for selector, value := range rawConf {
		switch typed := value.(type) {
		case string:
			secrets[selector] = types.NewStringSecret(sourceName, selector, typed)

		case map[string]any:
			values := make(map[string]types.Secret, len(typed))
			for key, raw := range typed {
				str, ok := raw.(string)
				if !ok {
					return nil, errorchain.NewWithMessagef(types.ErrInvalidSecretPayload,
						"inline credential '%s/%s' is not a string", selector, key)
				}

				values[key] = types.NewStringSecret(sourceName, selector+"/"+key, str)
			}

			credentials[selector] = types.NewCredentials(sourceName, selector, values)

		default:
			return nil, errorchain.NewWithMessagef(types.ErrInvalidSecretPayload,
				"inline secret '%s' must be either string or structured object", selector)
		}
	}

	return &provider{
		name:        sourceName,
		secrets:     secrets,
		credentials: credentials,
	}, nil
}

func (p *provider) Name() string                                             { return p.name }
func (p *provider) Type() string                                             { return ProviderType }
func (p *provider) Start(_ context.Context, _ func(types.ChangeEvent)) error { return nil }
func (p *provider) Stop(_ context.Context) error                             { return nil }

func (p *provider) ResolveSecret(_ context.Context, selector types.Selector) (types.Secret, error) {
	secret := p.secrets[selector.Value]
	if secret == nil {
		return nil, errorchain.NewWithMessagef(types.ErrSecretNotFound,
			"no inline string secret found for selector '%s'", selector.Value)
	}

	return secret, nil
}

func (p *provider) ResolveSecretSet(_ context.Context, _ types.Selector) ([]types.Secret, error) {
	secrets := make([]types.Secret, 0, len(p.secrets))
	for _, entry := range p.secrets {
		secrets = append(secrets, entry)
	}

	return secrets, nil
}

func (p *provider) ResolveCredentials(_ context.Context, selector types.Selector) (types.Credentials, error) {
	credentials := p.credentials[selector.Value]
	if credentials == nil {
		return nil, errorchain.NewWithMessagef(types.ErrSecretNotFound,
			"no inline credentials found for selector '%s'", selector.Value)
	}

	return credentials, nil
}
