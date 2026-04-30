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

package pem

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"

	"github.com/youmark/pkcs8"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

const (
	pemBlockTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	pemBlockTypePrivateKey          = "PRIVATE KEY"
	pemBlockTypeECPrivateKey        = "EC PRIVATE KEY"
	pemBlockTypeRSAPrivateKey       = "RSA PRIVATE KEY"
	pemBlockTypeCertificate         = "CERTIFICATE"
)

var errNoSuchKey = errors.New("no such key")

type keyStore []types.Secret

func newKeyStoreFromKey(privateKey crypto.Signer) (keyStore, error) {
	entry, err := createEntry(privateKey, "")
	if err != nil {
		return nil, err
	}

	return buildStore([]types.Secret{entry}, nil)
}

func newKeyStoreFromPEMFile(path, password string) (keyStore, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed to get information about %s", path).CausedBy(err)
	}

	if fileInfo.IsDir() {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration, "'%s' is not a file", path)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed to read %s", path).CausedBy(err)
	}

	return newKeyStoreFromPEMBytes(contents, password)
}

func newKeyStoreFromPEMBytes(contents []byte, password string) (keyStore, error) {
	blocks := readPEMBlocks(contents)

	var (
		entries []types.Secret
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
			return nil, errorchain.NewWithMessagef(pipeline.ErrInternal,
				"unsupported entry '%s' in the pem file", block.Type)
		}

		if err != nil {
			return nil, errorchain.NewWithMessagef(pipeline.ErrInternal,
				"failed to parse %d entry in the pem file", idx).CausedBy(err)
		}

		if cert != nil {
			certs = append(certs, cert)

			continue
		}

		entry, err := createEntry(key, block.Headers["X-Key-ID"])
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry)
	}

	return buildStore(entries, certs)
}

func (s keyStore) get(id string) (types.Secret, error) {
	for _, entry := range s {
		if entry.KeyID == id {
			return entry, nil
		}
	}

	return types.Secret{}, errorchain.NewWithMessagef(errNoSuchKey, "%s", id)
}

func (s keyStore) allEntries() []types.Secret {
	return s
}

func readPEMBlocks(data []byte) []*pem.Block {
	var blocks []*pem.Block

	for {
		block, next := pem.Decode(data)
		if block == nil {
			break
		}

		blocks = append(blocks, block)
		data = next
	}

	return blocks
}

func buildStore(entries []types.Secret, certs []*x509.Certificate) (keyStore, error) {
	if len(entries) == 0 {
		return nil, errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"no key material present in the keystore")
	}

	known := make(map[string]struct{}, len(entries))

	for idx, entry := range entries {
		signer, err := entry.AsSigner()
		if err != nil {
			return nil, errorchain.NewWithMessage(pipeline.ErrInternal,
				"invalid key material type in pem source").CausedBy(err)
		}

		chain := findChain(signer.Public(), certs)
		if len(chain) != 0 {
			if err = validateChain(chain); err != nil {
				return nil, err
			}
		}

		if entry.KeyID == "" {
			kid, kidErr := generateKeyID(chain, entry)
			if kidErr != nil {
				return nil, errorchain.NewWithMessagef(pipeline.ErrInternal,
					"failed generating kid for %d entry", idx+1).CausedBy(kidErr)
			}

			entry.KeyID = kid
		}

		if _, ok := known[entry.KeyID]; ok {
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
				"duplicate entry for key_id=%s found", entry.KeyID)
		}

		known[entry.KeyID] = struct{}{}
		entry.CertChain = chain
		entries[idx] = entry
	}

	return entries, nil
}

func createEntry(key any, keyID string) (types.Secret, error) {
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return types.Secret{
			KeyID:     keyID,
			Algorithm: "RSA",
			KeySize:   typed.Size() * 8,
			Type:      types.SecretTypeAsymmetric,
			Value:     typed,
		}, nil
	case *ecdsa.PrivateKey:
		return types.Secret{
			KeyID:     keyID,
			Algorithm: "ECDSA",
			KeySize:   typed.Params().BitSize,
			Type:      types.SecretTypeAsymmetric,
			Value:     typed,
		}, nil
	default:
		return types.Secret{}, errorchain.NewWithMessage(pipeline.ErrInternal,
			"unsupported key type; only rsa and ecdsa keys are supported")
	}
}

func generateKeyID(chain []*x509.Certificate, entry types.Secret) (string, error) {
	keyID := []byte(nil)
	if len(chain) != 0 {
		keyID = chain[0].SubjectKeyId
	}

	if len(keyID) == 0 {
		signer, err := entry.AsSigner()
		if err != nil {
			return "", err
		}

		keyID, err = pkix.SubjectKeyID(signer.Public())
		if err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(keyID), nil
}

func findChain(key crypto.PublicKey, certPool []*x509.Certificate) []*x509.Certificate {
	publicKey, ok := key.(interface {
		Equal(other crypto.PublicKey) bool
	})
	if !ok {
		return nil
	}

	for _, cert := range certPool {
		if publicKey.Equal(cert.PublicKey) {
			return buildChain([]*x509.Certificate{cert}, certPool)
		}
	}

	return nil
}

func buildChain(chain []*x509.Certificate, certPool []*x509.Certificate) []*x509.Certificate {
	child := chain[len(chain)-1]

	for _, cert := range certPool {
		if child.Equal(cert) {
			continue
		}

		if isIssuerOf(child, cert) {
			return buildChain(append(chain, cert), certPool)
		}
	}

	return chain
}

func isIssuerOf(child, issuer *x509.Certificate) bool {
	if len(child.AuthorityKeyId) != 0 && len(issuer.SubjectKeyId) != 0 {
		return bytes.Equal(child.AuthorityKeyId, issuer.SubjectKeyId)
	}

	return bytes.Equal(child.RawIssuer, issuer.RawSubject)
}

func validateChain(chain []*x509.Certificate) error {
	intermediates := make([]*x509.Certificate, 0, max(0, len(chain)-2))
	if len(chain) > 2 {
		intermediates = append(intermediates, chain[1:len(chain)-1]...)
	}

	err := pkix.ValidateCertificate(chain[0],
		pkix.WithRootCACertificates([]*x509.Certificate{chain[len(chain)-1]}),
		pkix.WithIntermediateCACertificates(intermediates),
	)
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration, "invalid certificate chain").CausedBy(err)
	}

	return nil
}
