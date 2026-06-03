// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pem

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"

	"github.com/youmark/pkcs8"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var errNoKeyMaterialPresent = errors.New("no key material present in the keystore")

type keyStore []provider.Secret

type keyEntry struct {
	keyID      string
	privateKey crypto.Signer
}

func newKeyStoreFromPEMBytes(contents []byte, password string) (keyStore, error) {
	blocks := readPEMBlocks(contents)

	var (
		entries []keyEntry
		certs   []*x509.Certificate
	)

	for idx, block := range blocks {
		var (
			key  any
			cert *x509.Certificate
			err  error
		)

		switch block.Type {
		case pemBlockTypeEncryptedPrivateKey:
			key, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, stringx.ToBytes(password))
		case pemBlockTypePrivateKey:
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case pemBlockTypeECPrivateKey:
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case pemBlockTypeRSAPrivateKey:
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case pemBlockTypeCertificate:
			cert, err = x509.ParseCertificate(block.Bytes)
		default:
			return nil, errorchain.NewWithMessagef(provider.ErrInternal,
				"unsupported entry '%s' in the pem file", block.Type)
		}

		if err != nil {
			return nil, errorchain.NewWithMessagef(provider.ErrInternal,
				"failed to parse %d entry in the pem file", idx).CausedBy(err)
		}

		if cert != nil {
			certs = append(certs, cert)

			continue
		}

		keyID := block.Headers["X-Key-ID"]

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errorchain.NewWithMessage(provider.ErrInternal,
				"unsupported key type; key does not implement crypto.Signer")
		}

		entries = append(entries, keyEntry{
			keyID:      keyID,
			privateKey: signer,
		})
	}

	return buildStore(entries, certs)
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
	return s, nil
}

func (s keyStore) getCertificateBundle(_ context.Context, _ provider.Selector) (provider.CertificateBundle, error) {
	return nil, provider.ErrUnsupportedOperation
}

func (s keyStore) sameKind(other store) bool {
	_, ok := other.(keyStore)

	return ok
}

func buildStore(entries []keyEntry, certs []*x509.Certificate) (keyStore, error) {
	if len(entries) == 0 {
		return nil, errorchain.New(provider.ErrConfiguration).
			CausedBy(errNoKeyMaterialPresent)
	}

	known := make(map[string]struct{}, len(entries))
	result := make([]provider.Secret, len(entries))

	for idx, entry := range entries {
		chain := findChain(entry.privateKey.Public(), certs)
		if len(chain) != 0 {
			if err := validateChain(chain); err != nil {
				return nil, err
			}
		}

		keyID := entry.keyID
		if keyID == "" {
			generated, err := generateKeyID(chain, entry.privateKey)
			if err != nil {
				return nil, errorchain.NewWithMessagef(provider.ErrInternal,
					"failed generating key id for %d entry", idx+1).CausedBy(err)
			}

			keyID = generated
		}

		if _, ok := known[keyID]; ok {
			return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
				"duplicate entry for key id=%s found", keyID)
		}

		known[keyID] = struct{}{}

		result[idx] = provider.NewAsymmetricKeySecret(keyID, keyID, entry.privateKey, chain)
	}

	return result, nil
}

func generateKeyID(chain []*x509.Certificate, signer crypto.Signer) (string, error) {
	keyID := []byte(nil)
	if len(chain) != 0 {
		keyID = chain[0].SubjectKeyId
	}

	if len(keyID) == 0 {
		var err error

		keyID, err = pkix.SubjectKeyID(signer.Public())
		if err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(keyID), nil
}
