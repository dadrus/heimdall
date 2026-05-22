package pem

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"

	"github.com/youmark/pkcs8"

	"github.com/dadrus/heimdall/internal/secrets2/provider"
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

type keyStore []provider.Secret

type keyEntry struct {
	keyID      string
	privateKey crypto.Signer
}

func newKeyStoreFromKey(selector string, privateKey crypto.Signer) (keyStore, error) {
	entry := keyEntry{
		keyID:      selector,
		privateKey: privateKey,
	}

	return buildStore([]keyEntry{entry}, nil)
}

func newKeyStoreFromPEMFile(path, password string) (keyStore, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"failed to get information about %s", path).CausedBy(err)
	}

	if fileInfo.IsDir() {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration, "'%s' is not a file", path)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"failed to read %s", path).CausedBy(err)
	}

	return newKeyStoreFromPEMBytes(contents, password)
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

func (s keyStore) get(selector string) (provider.Secret, error) {
	for _, entry := range s {
		if entry.Selector() == selector {
			return entry, nil
		}
	}

	return nil, errorchain.NewWithMessagef(provider.ErrSecretNotFound, "%s", selector)
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

func buildStore(entries []keyEntry, certs []*x509.Certificate) (keyStore, error) {
	if len(entries) == 0 {
		return nil, errorchain.NewWithMessage(provider.ErrConfiguration,
			"no key material present in the keystore")
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
	intermediates := make([]*x509.Certificate, 0, max(0, len(chain)-2)) //nolint:mnd
	if len(chain) > 2 {                                                 //nolint:mnd
		intermediates = append(intermediates, chain[1:len(chain)-1]...)
	}

	err := pkix.ValidateCertificate(chain[0],
		pkix.WithRootCACertificates([]*x509.Certificate{chain[len(chain)-1]}),
		pkix.WithIntermediateCACertificates(intermediates),
	)
	if err != nil {
		return errorchain.NewWithMessage(provider.ErrConfiguration,
			"invalid certificate chain").CausedBy(err)
	}

	return nil
}
