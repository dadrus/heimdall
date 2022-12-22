package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"

	"github.com/youmark/pkcs8"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/pkix"
)

const (
	pemBlockTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	pemBlockTypePrivateKey          = "PRIVATE KEY"
	pemBlockTypeECPrivateKey        = "EC PRIVATE KEY"
	pemBlockTypeRSAPrivateKey       = "RSA PRIVATE KEY"
	pemBlockTypeCertificate         = "CERTIFICATE"

	AlgRSA   = "RSA"
	AlgECDSA = "ECDSA"
)

var ErrNoSuchKey = errors.New("no such key")

type KeyStore interface {
	GetKey(id string) (*Entry, error)
	Entries() []*Entry
}

type keyStore []*Entry

func (ks keyStore) GetKey(id string) (*Entry, error) {
	for _, entry := range ks {
		if entry.KeyID == id {
			return entry, nil
		}
	}

	return nil, errorchain.NewWithMessagef(ErrNoSuchKey, "%s", id)
}

func (ks keyStore) Entries() []*Entry {
	return ks
}

func NewKeyStoreFromKey(privateKey crypto.Signer) (KeyStore, error) {
	entry, err := createEntry(privateKey, "")
	if err != nil {
		return nil, err
	}

	return verifyAndBuildKeyStore([]*Entry{entry}, nil)
}

func NewKeyStoreFromPEMFile(pemFilePath, password string) (KeyStore, error) {
	fInfo, err := os.Stat(pemFilePath)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to get information about %s", pemFilePath).CausedBy(err)
	}

	if fInfo.IsDir() {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "'%s' is not a file", pemFilePath)
	}

	contents, err := os.ReadFile(pemFilePath)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to read %s", pemFilePath).CausedBy(err)
	}

	return NewKeyStoreFromPEMBytes(contents, password)
}

func NewKeyStoreFromPEMBytes(pemBytes []byte, password string) (KeyStore, error) {
	return createKeyStore(readPEMContents(pemBytes), password)
}

func createKeyStore(blocks []*pem.Block, password string) (keyStore, error) {
	var (
		entries []*Entry
		certs   []*x509.Certificate
	)

	for idx, block := range blocks {
		var (
			cert *x509.Certificate
			key  any
			err  error
		)

		switch block.Type {
		case pemBlockTypeEncryptedPrivateKey:
			// PKCS#8 (PKCS#5 (v2.0) algorithms)
			key, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
		case pemBlockTypePrivateKey:
			// PKCS#8 - unencrypted
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case pemBlockTypeECPrivateKey:
			// PKCS#1 - unencrypted
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case pemBlockTypeRSAPrivateKey:
			// PKCS#1 - unencrypted
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case pemBlockTypeCertificate:
			cert, err = x509.ParseCertificate(block.Bytes)
		default:
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"unsupported entry '%s' entry in the pem file", block.Type)
		}

		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to parse %d entry in the pem file", idx).CausedBy(err)
		}

		if cert != nil {
			certs = append(certs, cert)
		} else {
			entry, err := createEntry(key, block.Headers["X-Key-ID"])
			if err != nil {
				return nil, err
			}

			entries = append(entries, entry)
		}
	}

	return verifyAndBuildKeyStore(entries, certs)
}

func verifyAndBuildKeyStore(entries []*Entry, certs []*x509.Certificate) (keyStore, error) {
	known := make(map[string]bool)

	for idx, entry := range entries {
		chain := FindChain(entry.PrivateKey.Public(), certs)
		if len(chain) != 0 {
			if err := ValidateChain(chain); err != nil {
				return nil, err
			}
		}

		if len(entry.KeyID) == 0 {
			kid, err := generateKeyID(chain, entry)
			if err != nil {
				return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
					"failed generating kid for %d entry", idx+1).CausedBy(err)
			}

			entry.KeyID = kid
		}

		if _, ok := known[entry.KeyID]; ok {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"duplicate entry for key_id=%s found", entry.KeyID)
		}

		known[entry.KeyID] = true

		entry.CertChain = chain
	}

	return entries, nil
}

func generateKeyID(chain []*x509.Certificate, entry *Entry) (string, error) {
	var (
		keyID []byte
		err   error
	)

	if len(chain) != 0 {
		// use subject key identifier from certificate (if present)
		keyID = chain[0].SubjectKeyId
	}

	// if certificate did not have subject key identifier set
	// calculate subject key identifier and use it
	if len(keyID) == 0 {
		keyID, err = pkix.SubjectKeyID(entry.PrivateKey.Public())
		if err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(keyID), nil
}

func readPEMContents(data []byte) []*pem.Block {
	var (
		blocks []*pem.Block
		block  *pem.Block
	)

	next := data

	for {
		block, next = pem.Decode(next)
		blocks = append(blocks, block)

		if len(next) == 0 {
			break
		}
	}

	return blocks
}

func createEntry(key any, keyID string) (*Entry, error) {
	var (
		sigKey    crypto.Signer
		algorithm string
		size      int
	)

	switch typedKey := key.(type) {
	case *rsa.PrivateKey:
		const bitsInByte = 8

		algorithm = AlgRSA
		sigKey = typedKey
		size = typedKey.Size() * bitsInByte
	case *ecdsa.PrivateKey:
		algorithm = AlgECDSA
		sigKey = typedKey
		size = typedKey.Params().BitSize
	default:
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"unsupported key type; only rsa and ecdsa keys are supported")
	}

	return &Entry{
		KeyID:      keyID,
		Alg:        algorithm,
		KeySize:    size,
		PrivateKey: sigKey,
	}, nil
}
