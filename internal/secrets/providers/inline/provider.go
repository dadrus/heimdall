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
	"strings"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/registry"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const ProviderType = "inline"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(ProviderType, types.ProviderFactoryFunc(newProvider))
}

type provider struct {
	secrets     map[string]types.Secret
	credentials map[string]types.Credentials
}

func newProvider(args types.ProviderArgs) (types.Provider, error) {
	if len(args.Config) == 0 {
		return nil, errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"inline provider config must not be empty")
	}

	secrets := make(map[string]types.Secret, len(args.Config))
	credentials := make(map[string]types.Credentials, len(args.Config))

	for selector, value := range args.Config {
		if strings.Contains(selector, "/") {
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
				"inline selector '%s' must not contain '/'", selector)
		}

		switch typed := value.(type) {
		case string:
			secrets[selector] = types.NewStringSecret(selector, typed)

		case map[string]any:
			credentials[selector] = types.NewCredentials(selector, typed)

		default:
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
				"inline secret '%s' must be either string or structured object", selector)
		}
	}

	return &provider{
		secrets:     secrets,
		credentials: credentials,
	}, nil
}

func (p *provider) Dependencies() []types.Reference { return nil }
func (p *provider) Type() string                    { return ProviderType }
func (p *provider) Start(_ context.Context) error   { return nil }
func (p *provider) Stop(_ context.Context) error    { return nil }

func (p *provider) GetSecret(_ context.Context, selector types.Selector) (types.Secret, error) {
	secret := p.secrets[selector.Value]
	if secret == nil {
		return nil, errorchain.NewWithMessagef(types.ErrSecretNotFound,
			"no inline string secret found for selector '%s'", selector.Value)
	}

	return secret, nil
}

func (p *provider) GetSecretSet(_ context.Context, selector types.Selector) ([]types.Secret, error) {
	if selector.Value != "" {
		return nil, errorchain.NewWithMessagef(types.ErrUnsupportedOperation,
			"inline secret sets are only supported for the provider root, got selector '%s'", selector.Value)
	}

	secrets := make([]types.Secret, 0, len(p.secrets))
	for _, entry := range p.secrets {
		secrets = append(secrets, entry)
	}

	return secrets, nil
}

func (p *provider) GetCredentials(_ context.Context, selector types.Selector) (types.Credentials, error) {
	credentials := p.credentials[selector.Value]
	if credentials == nil {
		return nil, errorchain.NewWithMessagef(types.ErrCredentialsNotFound,
			"no credentials found for selector '%s'", selector.Value)
	}

	return credentials, nil
}
