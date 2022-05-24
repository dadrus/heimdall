package keystore

// nolint
// md5 is used for fingerprint generation only
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"

	"github.com/youmark/pkcs8"
	"golang.org/x/exp/maps"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	pemBlockTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	pemBlockTypePrivateKey          = "PRIVATE KEY"
	pemBlockTypeECPrivateKey        = "EC PRIVATE KEY"
	pemBlockTypeRSAPrivateKey       = "RSA PRIVATE KEY"

	AlgRSA   = "RSA"
	AlgECDSA = "ECDSA"
)

var ErrNoSuchKey = errors.New("no such key")

type KeyStore interface {
	GetKey(id string) (*Entry, error)
	Entries() []*Entry
}

type Entry struct {
	KeyID      string
	Alg        string
	KeySize    int
	PrivateKey crypto.Signer
	CertChain  []*x509.Certificate
}

type keyStore map[string]*Entry

func (ks keyStore) GetKey(id string) (*Entry, error) {
	entry, ok := ks[id]
	if !ok {
		return nil, errorchain.NewWithMessagef(ErrNoSuchKey, "%s", id)
	}

	return entry, nil
}

func (ks keyStore) Entries() []*Entry {
	return maps.Values(ks)
}

func NewKeyStoreFromKey(privateKey crypto.Signer) (KeyStore, error) {
	entry, err := createEntry(privateKey)
	if err != nil {
		return nil, err
	}

	return keyStore{entry.KeyID: entry}, nil
}

func NewKeyStoreFromPEMFile(pemFilePath, password string) (KeyStore, error) {
	fInfo, err := os.Stat(pemFilePath)
	if err != nil {
		return nil, err
	}

	if fInfo.IsDir() {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrConfiguration, "'%s' is not a file", pemFilePath)
	}

	contents, err := os.ReadFile(pemFilePath)
	if err != nil {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrConfiguration, "failed to read %s", pemFilePath).
			CausedBy(err)
	}

	return NewKeyStoreFromPEMBytes(contents, password)
}

func NewKeyStoreFromPEMBytes(pemBytes []byte, password string) (KeyStore, error) {
	return loadKeys(readPEMContents(pemBytes), password)
}

func loadKeys(blocks []*pem.Block, password string) (keyStore, error) {
	ks := make(keyStore)

	for idx, block := range blocks {
		var (
			key any
			err error
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
		default:
			return nil, errorchain.
				NewWithMessagef(heimdall.ErrInternal, "unsupported entry '%s' entry in the pem file", block.Type)
		}

		if err != nil {
			return nil, errorchain.
				NewWithMessagef(heimdall.ErrInternal, "failed to parse %d entry in the pem file", idx).
				CausedBy(err)
		}

		entry, err := createEntry(key)
		if err != nil {
			return nil, err
		}

		ks[entry.KeyID] = entry
	}

	return ks, nil
}

func readPEMContents(data []byte) []*pem.Block {
	var blocks []*pem.Block

	block, next := pem.Decode(data)
	blocks = append(blocks, block)

	for len(next) != 0 {
		block, next = pem.Decode(next)
		blocks = append(blocks, block)
	}

	return blocks
}

func createEntry(key any) (*Entry, error) {
	var (
		sigKey    crypto.Signer
		algorithm string
		size      int
	)

	switch typ := key.(type) {
	case *rsa.PrivateKey:
		const bitsInByte = 8

		algorithm = AlgRSA
		sigKey = typ
		size = typ.Size() * bitsInByte
	case *ecdsa.PrivateKey:
		algorithm = AlgECDSA
		sigKey = typ
		size = typ.Params().BitSize
	default:
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "unsupported key type")
	}

	hash, err := fingerprint(sigKey.Public())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed calculating fingerprint for signature key").CausedBy(err)
	}

	return &Entry{
		KeyID:      hex.EncodeToString(hash),
		Alg:        algorithm,
		KeySize:    size,
		PrivateKey: sigKey,
	}, nil
}

func fingerprint(key crypto.PublicKey) ([]byte, error) {
	derEncoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	// nolint: gosec
	// need it for fingerprint only
	hash := sha1.New()

	if _, err = hash.Write(derEncoded); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
