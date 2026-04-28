package nonce

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var ErrNonceInvalid = errors.New("nonce error")

type (
	Key struct {
		KID   string
		Value []byte
	}

	KeyResolver interface {
		ResolveKey(kid string) (Key, error)
	}

	KeyResolverFunc func(kid string) (Key, error)
)

func (f KeyResolverFunc) ResolveKey(kid string) (Key, error) {
	return f(kid)
}

type payload struct {
	IssuedAt int64
	Binding  [nonceBindingSize]byte
}

func NewNonce(key Key, opts ...CreateOption) (string, error) {
	cfg := createConfig{}
	for _, opt := range opts {
		opt.applyCreate(&cfg)
	}

	data := payload{
		IssuedAt: time.Now().UTC().Unix(),
		Binding:  cfg.binding,
	}

	return data.encode(key)
}

func ValidateNonce(value string, resolver KeyResolver, opts ...ValidateOption) error {
	cfg := validateConfig{}
	now := time.Now().UTC()

	for _, opt := range opts {
		opt.applyValidate(&cfg)
	}

	var actual payload
	if err := actual.decode(resolver, value); err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(cfg.binding[:], actual.Binding[:]) != 1 {
		return errorchain.NewWithMessage(ErrNonceInvalid, "nonce binding mismatch")
	}

	issuedAt := time.Unix(actual.IssuedAt, 0).UTC()

	if issuedAt.After(now) {
		return errorchain.NewWithMessage(ErrNonceInvalid, "nonce has been issued in the future")
	}

	if cfg.maxAge > 0 && issuedAt.Before(now.Add(-cfg.maxAge)) {
		return errorchain.NewWithMessage(ErrNonceInvalid, "nonce is too old")
	}

	return nil
}

func (p *payload) encode(key Key) (string, error) {
	var (
		nonce         [nonceRandomSize]byte
		rawPayload    [noncePayloadSize]byte
		ciphertextBuf [noncePayloadSize + nonceAEADTagSize]byte
	)

	if len(key.KID) == 0 {
		return "", errorchain.NewWithMessage(ErrNonceInvalid, "nonce key id is invalid")
	}

	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errorchain.NewWithMessage(pipeline.ErrInternal, "Failed to generate random bytes").
			CausedBy(err)
	}

	aead, err := newCipher(key.Value, nonce[:])
	if err != nil {
		return "", err
	}

	rawPayload[0] = noncePayloadVersion
	binary.BigEndian.PutUint64(rawPayload[1:9], uint64(p.IssuedAt))
	copy(rawPayload[9:41], p.Binding[:])

	ciphertext := aead.Seal(ciphertextBuf[:0], nonce[:nonceAEADNonceSize], rawPayload[:], nil)
	nonceLen := base64.RawURLEncoding.EncodedLen(len(nonce))
	ciphertextLen := base64.RawURLEncoding.EncodedLen(len(ciphertext))

	out := make([]byte, len(key.KID)+1+nonceLen+1+ciphertextLen)

	copy(out, key.KID)

	pos := len(key.KID)
	out[pos] = '.'
	pos++

	base64.RawURLEncoding.Encode(out[pos:pos+nonceLen], nonce[:])
	pos += nonceLen

	out[pos] = '.'
	pos++

	base64.RawURLEncoding.Encode(out[pos:], ciphertext)

	return string(out), nil
}

func (p *payload) decode(resolver KeyResolver, value string) error {
	var (
		nonce         [nonceRandomSize]byte
		ciphertextBuf [maxEncryptedNonceLen]byte
	)

	if len(value) == 0 || len(value) > maxEncryptedNonceLen {
		return errorchain.NewWithMessage(ErrNonceInvalid, "invalid format")
	}

	kid, rest, ok := strings.Cut(value, ".")
	if !ok {
		return errorchain.NewWithMessage(ErrNonceInvalid, "invalid format")
	}

	nonceB64, ciphertextB64, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(ciphertextB64, ".") {
		return errorchain.NewWithMessage(ErrNonceInvalid, "invalid format")
	}

	if base64.RawURLEncoding.DecodedLen(len(nonceB64)) != nonceRandomSize {
		return errorchain.NewWithMessage(ErrNonceInvalid, "invalid format")
	}

	key, err := resolver.ResolveKey(kid)
	if err != nil {
		return errorchain.NewWithMessage(ErrNonceInvalid, "key not found").CausedBy(err)
	}

	n, err := base64.RawURLEncoding.Decode(nonce[:], stringx.ToBytes(nonceB64))
	if err != nil {
		return errorchain.NewWithMessage(ErrNonceInvalid, "decoding nonce failed").
			CausedBy(err)
	}

	if n != nonceRandomSize {
		return errorchain.NewWithMessage(ErrNonceInvalid, "invalid format")
	}

	ciphertextDecodedLen := base64.RawURLEncoding.DecodedLen(len(ciphertextB64))

	n, err = base64.RawURLEncoding.Decode(ciphertextBuf[:ciphertextDecodedLen], stringx.ToBytes(ciphertextB64))
	if err != nil {
		return errorchain.NewWithMessage(ErrNonceInvalid, "decoding ciphertext failed").
			CausedBy(err)
	}

	ciphertext := ciphertextBuf[:n]

	aead, err := newCipher(key.Value, nonce[:])
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrInternal, "failed creating cipher").
			CausedBy(err)
	}

	rawPayload, err := aead.Open(ciphertext[:0], nonce[:nonceAEADNonceSize], ciphertext, nil)
	if err != nil {
		return errorchain.NewWithMessage(ErrNonceInvalid, "failed to decrypt").CausedBy(err)
	}

	if len(rawPayload) != noncePayloadSize {
		return errorchain.NewWithMessage(ErrNonceInvalid, "unexpected payload size")
	}

	if rawPayload[0] != noncePayloadVersion {
		return errorchain.NewWithMessage(ErrNonceInvalid, "unsupported payload version")
	}

	iat := int64(binary.BigEndian.Uint64(rawPayload[1:9]))
	if iat <= 0 {
		return errorchain.NewWithMessage(ErrNonceInvalid, "bad issued at value")
	}

	p.IssuedAt = iat
	copy(p.Binding[:], rawPayload[9:41])

	return nil
}

func newCipher(masterKey, nonce []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, masterKey, nonce, nonceHKDFInfo, nonceAEADKeySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
