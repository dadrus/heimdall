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

	"github.com/dadrus/heimdall/internal/secrets2/provider"
	"github.com/dadrus/heimdall/internal/secrets2/registry"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const ProviderType = "inline"

// by intention. Used only during application bootstrap.
//
//nolint:gochecknoinits
func init() {
	registry.Register(ProviderType, provider.FactoryFunc(newProvider))
}

type inlineProvider struct {
	secrets     map[string]provider.Secret
	credentials map[string]provider.Credentials
}

func newProvider(args provider.Args) (provider.Provider, error) {
	if len(args.Config) == 0 {
		return nil, errorchain.NewWithMessage(provider.ErrConfiguration,
			"inline provider config must not be empty")
	}

	secrets := make(map[string]provider.Secret, len(args.Config))
	credentials := make(map[string]provider.Credentials, len(args.Config))

	for selector, value := range args.Config {
		if strings.Contains(selector, "/") {
			return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
				"inline selector '%s' must not contain '/'", selector)
		}

		switch typed := value.(type) {
		case string:
			secrets[selector] = provider.NewStringSecret(selector, typed)

		case map[string]any:
			credentials[selector] = provider.NewCredentials(selector, typed)

		default:
			return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
				"inline secret '%s' must be either string or structured object", selector)
		}
	}

	return &inlineProvider{
		secrets:     secrets,
		credentials: credentials,
	}, nil
}

func (*inlineProvider) Dependencies() []provider.Reference { return nil }
func (*inlineProvider) IsNamespaceAware() bool             { return false }
func (*inlineProvider) Type() string                       { return ProviderType }
func (*inlineProvider) Start(_ context.Context) error      { return nil }
func (*inlineProvider) Stop(_ context.Context) error       { return nil }

func (p *inlineProvider) GetSecret(
	_ context.Context,
	selector provider.Selector,
) (provider.Secret, error) {
	secret := p.secrets[selector.Value]
	if secret == nil {
		return nil, errorchain.NewWithMessagef(
			provider.ErrSecretNotFound,
			"no inline string secret found for selector '%s'", selector.Value,
		)
	}

	return secret, nil
}

func (p *inlineProvider) GetSecretSet(
	_ context.Context,
	selector provider.Selector,
) ([]provider.Secret, error) {
	if selector.Value != "" {
		return nil, errorchain.NewWithMessagef(
			provider.ErrUnsupportedOperation,
			"inline secret sets are only supported for the provider root, got selector '%s'", selector.Value,
		)
	}

	secrets := make([]provider.Secret, 0, len(p.secrets))
	for _, entry := range p.secrets {
		secrets = append(secrets, entry)
	}

	return secrets, nil
}

func (p *inlineProvider) GetCredentials(
	_ context.Context,
	selector provider.Selector,
) (provider.Credentials, error) {
	credentials := p.credentials[selector.Value]
	if credentials == nil {
		return nil, errorchain.NewWithMessagef(
			provider.ErrCredentialsNotFound,
			"no credentials found for selector '%s'", selector.Value,
		)
	}

	return credentials, nil
}

func (p *inlineProvider) GetCertificateBundle(
	_ context.Context,
	_ provider.Selector,
) (provider.CertificateBundle, error) {
	return nil, provider.ErrUnsupportedOperation
}
