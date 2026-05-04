package pem

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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

type keyStore []types.Secret

func newKeyStoreFromKey(source, selector string, privateKey crypto.Signer) (keyStore, error) {
	entry := types.NewAsymmetricKeySecret(source, selector, selector, privateKey, nil)

	return buildStore(source, []types.AsymmetricKeySecret{entry}, nil)
}

func newKeyStoreFromPEMFile(source, path, password string) (keyStore, error) {
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

	return newKeyStoreFromPEMBytes(source, contents, password)
}

func newKeyStoreFromPEMBytes(source string, contents []byte, password string) (keyStore, error) {
	blocks := readPEMBlocks(contents)

	var (
		entries []types.AsymmetricKeySecret
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

		keyID := block.Headers["X-Key-ID"]

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errorchain.NewWithMessage(pipeline.ErrInternal,
				"unsupported key type; key does not implement crypto.Signer")
		}

		entries = append(entries, types.NewAsymmetricKeySecret(source, keyID, keyID, signer, nil))
	}

	return buildStore(source, entries, certs)
}

func (s keyStore) get(selector string) (types.Secret, error) {
	for _, entry := range s {
		if entry.Selector() == selector {
			return entry, nil
		}
	}

	return nil, errorchain.NewWithMessagef(types.ErrSecretNotFound, "%s", selector)
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

func buildStore(source string, entries []types.AsymmetricKeySecret, certs []*x509.Certificate) (keyStore, error) {
	if len(entries) == 0 {
		return nil, errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"no key material present in the keystore")
	}

	known := make(map[string]struct{}, len(entries))
	result := make([]types.Secret, len(entries))

	for idx, entry := range entries {
		chain := findChain(entry.PrivateKey().Public(), certs)
		if len(chain) != 0 {
			if err := validateChain(chain); err != nil {
				return nil, err
			}
		}

		keyID := entry.KeyID()
		if keyID == "" {
			generated, err := generateKeyID(chain, entry.PrivateKey())
			if err != nil {
				return nil, errorchain.NewWithMessagef(pipeline.ErrInternal,
					"failed generating kid for %d entry", idx+1).CausedBy(err)
			}

			keyID = generated
		}

		if _, ok := known[keyID]; ok {
			return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
				"duplicate entry for key_id=%s found", keyID)
		}

		known[keyID] = struct{}{}

		selector := entry.Selector()
		if selector == "" {
			selector = keyID
		}

		result[idx] = types.NewAsymmetricKeySecret(source, selector, keyID, entry.PrivateKey(), chain)
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
	intermediates := make([]*x509.Certificate, 0, max(0, len(chain)-2))
	if len(chain) > 2 {
		intermediates = append(intermediates, chain[1:len(chain)-1]...)
	}

	err := pkix.ValidateCertificate(chain[0],
		pkix.WithRootCACertificates([]*x509.Certificate{chain[len(chain)-1]}),
		pkix.WithIntermediateCACertificates(intermediates),
	)
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"invalid certificate chain").CausedBy(err)
	}

	return nil
}
