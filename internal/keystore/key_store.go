package keystore

// nolint
// md5 is used for fingerprint generation only
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
		hash      []byte
	)

	switch typedKey := key.(type) {
	case *rsa.PrivateKey:
		const bitsInByte = 8

		algorithm = AlgRSA
		sigKey = typedKey
		size = typedKey.Size() * bitsInByte
		hash = hashKeyBytes(x509.MarshalPKCS1PublicKey(&typedKey.PublicKey))
	case *ecdsa.PrivateKey:
		algorithm = AlgECDSA
		sigKey = typedKey
		size = typedKey.Params().BitSize
		hash = hashKeyBytes(elliptic.Marshal(typedKey.PublicKey.Curve, typedKey.PublicKey.X, typedKey.PublicKey.Y))
	default:
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "unsupported key type")
	}

	return &Entry{
		KeyID:      hex.EncodeToString(hash),
		Alg:        algorithm,
		KeySize:    size,
		PrivateKey: sigKey,
	}, nil
}

func hashKeyBytes(val []byte) []byte {
	// nolint: gosec
	// used for fingerprinting
	md := sha1.New()
	md.Write(val)

	return md.Sum(nil)
}
