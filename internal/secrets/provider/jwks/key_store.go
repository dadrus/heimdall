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

package jwks

import (
	"context"
	"crypto"
	"errors"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
)

const minOctetKeySize = 16

var errNoKeyMaterialPresent = errors.New("no key material present in the jwks file")

type keyStore []provider.Secret

func newKeyStore(jwks jose.JSONWebKeySet) (keyStore, error) {
	known := make(map[string]struct{}, len(jwks.Keys))
	secrets := make([]provider.Secret, 0, len(jwks.Keys))

	for idx := range jwks.Keys {
		jwk := jwks.Keys[idx]
		kid := strings.TrimSpace(jwk.KeyID)

		if kid == "" {
			return nil, errorchain.NewWithMessagef(
				provider.ErrConfiguration,
				"jwk at index %d is missing required kid",
				idx,
			)
		}

		if _, ok := known[kid]; ok {
			return nil, errorchain.NewWithMessagef(
				provider.ErrConfiguration,
				"duplicate jwk kid '%s' found",
				kid,
			)
		}

		known[kid] = struct{}{}

		secret, err := toSecret(jwk)
		if err != nil {
			return nil, err
		}

		secrets = append(secrets, secret)
	}

	if len(secrets) == 0 {
		return nil, errorchain.New(provider.ErrConfiguration).
			CausedBy(errNoKeyMaterialPresent)
	}

	return secrets, nil
}

func toSecret(jwk jose.JSONWebKey) (provider.Secret, error) {
	switch key := jwk.Key.(type) {
	case crypto.Signer:
		return toAsymmetricKeySecret(jwk, key)
	case []byte:
		return toSymmetricKeySecret(jwk, key)
	default:
		return nil, errorchain.NewWithMessagef(
			provider.ErrConfiguration,
			"unsupported jwk key material for kid '%s'", jwk.KeyID,
		)
	}
}

func toSymmetricKeySecret(jwk jose.JSONWebKey, value []byte) (provider.Secret, error) {
	if len(value) < minOctetKeySize {
		return nil, errorchain.NewWithMessagef(
			provider.ErrConfiguration,
			"oct jwk with kid '%s' contains key material shorter than %d bytes",
			jwk.KeyID,
			minOctetKeySize,
		)
	}

	return provider.NewSymmetricKeySecret(jwk.KeyID, jwk.KeyID, jwk.Algorithm, value), nil
}

func toAsymmetricKeySecret(jwk jose.JSONWebKey, signer crypto.Signer) (provider.Secret, error) {
	chain := pkix.FindChain(signer.Public(), jwk.Certificates)
	if len(chain) != 0 {
		if err := pkix.ValidateChain(chain); err != nil {
			return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
				"invalid certificate chain for kid '%s'", jwk.KeyID).CausedBy(err)
		}
	} else if len(jwk.Certificates) != 0 {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"malformed certificate chain for kid '%s'", jwk.KeyID)
	}

	return provider.NewAsymmetricKeySecret(jwk.KeyID, jwk.KeyID, signer, chain), nil
}

func (s keyStore) getSecret(_ context.Context, selector provider.Selector) (provider.Secret, error) {
	if len(s) == 0 {
		return nil, provider.ErrSecretNotFound
	}

	if len(selector.Value) == 0 {
		return s[0], nil
	}

	for _, entry := range s {
		if entry.Selector() == selector.Value {
			return entry, nil
		}
	}

	return nil, errorchain.NewWithMessagef(provider.ErrSecretNotFound, "%s", selector)
}

func (s keyStore) getSecretSet(_ context.Context, _ provider.Selector) ([]provider.Secret, error) {
	if len(s) == 0 {
		return nil, provider.ErrSecretSetNotFound
	}

	return s, nil
}

func (s keyStore) getCertificateBundle(
	_ context.Context,
	_ provider.Selector,
) (provider.CertificateBundle, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (s keyStore) sameKind(other store) bool {
	_, ok := other.(keyStore)

	return ok
}
