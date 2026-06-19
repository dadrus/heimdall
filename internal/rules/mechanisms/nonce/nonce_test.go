package nonce

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewNonce(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		key    Key
		assert func(t *testing.T, nonce string, err error)
	}{
		"fails without key id": {
			key: Key{
				Value: []byte("0123456789abcdef0123456789abcdef"),
			},
			assert: func(t *testing.T, nonce string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "key id")
				require.Empty(t, nonce)
			},
		},
		"succeeds": {
			key: Key{
				KID:   "test-key",
				Value: []byte("0123456789abcdef0123456789abcdef"),
			},
			assert: func(t *testing.T, nonce string, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotEmpty(t, nonce)

				parts := strings.Split(nonce, ".")
				require.Len(t, parts, 3)
				require.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("test-key")), parts[0])
			},
		},
		"succeeds with key id containing separator": {
			key: Key{
				KID:   "test.key",
				Value: []byte("0123456789abcdef0123456789abcdef"),
			},
			assert: func(t *testing.T, nonce string, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotEmpty(t, nonce)

				parts := strings.Split(nonce, ".")
				require.Len(t, parts, 3)
				require.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("test.key")), parts[0])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			nonce, err := NewNonce(tc.key)

			// THEN
			tc.assert(t, nonce, err)
		})
	}
}

func TestValidateNonce(t *testing.T) {
	t.Parallel()

	key := Key{
		KID:   "test-key",
		Value: []byte("0123456789abcdef0123456789abcdef"),
	}

	resolver := KeyResolverFunc(func(kid string) (Key, error) {
		if kid != key.KID {
			return Key{}, ErrNonceInvalid
		}

		return key, nil
	})

	var binding [nonceBindingSize]byte
	copy(binding[:], []byte("test-binding"))

	validNonce, err := NewNonce(key, WithBinding(binding))
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		nonce        string
		validateOpts []ValidateOption
		assert       func(t *testing.T, err error)
	}{
		"fails on empty nonce": {
			nonce: "",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid format")
			},
		},
		"fails on missing separators": {
			nonce: "foo",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid format")
			},
		},
		"fails on missing key id": {
			nonce: "." +
				base64.RawURLEncoding.EncodeToString(make([]byte, nonceRandomSize)) +
				"." +
				base64.RawURLEncoding.EncodeToString(make([]byte, noncePayloadSize+nonceAEADTagSize)),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid format")
			},
		},
		"fails on key id encoding": {
			nonce: "||||." +
				base64.RawURLEncoding.EncodeToString(make([]byte, nonceRandomSize)) +
				"." +
				base64.RawURLEncoding.EncodeToString(make([]byte, noncePayloadSize+nonceAEADTagSize)),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "decoding key id failed")
			},
		},
		"fails on missing encrypted payload": {
			nonce: base64.RawURLEncoding.EncodeToString([]byte("kid")) + ".nonce",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid format")
			},
		},
		"fails on too many separators": {
			nonce: validNonce + ".foo",
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid format")
			},
		},
		"fails on invalid nonce size": {
			nonce: base64.RawURLEncoding.EncodeToString([]byte("kid")) +
				"." +
				base64.RawURLEncoding.EncodeToString(make([]byte, nonceRandomSize-1)) + ".baz",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid format")
			},
		},
		"fails on nonce encoding": {
			nonce: base64.RawURLEncoding.EncodeToString([]byte("test-key")) + "." +
				strings.Repeat("|", base64.RawURLEncoding.EncodedLen(nonceRandomSize)) +
				"." +
				base64.RawURLEncoding.EncodeToString(make([]byte, noncePayloadSize+nonceAEADTagSize)),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "decoding nonce failed")
			},
		},
		"fails on invalid ciphertext size": {
			nonce: base64.RawURLEncoding.EncodeToString([]byte("test-key")) + "." +
				base64.RawURLEncoding.EncodeToString(make([]byte, nonceRandomSize)) +
				"." +
				base64.RawURLEncoding.EncodeToString(make([]byte, noncePayloadSize+nonceAEADTagSize-1)),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "invalid format")
			},
		},
		"fails on cipher encoding": {
			nonce: base64.RawURLEncoding.EncodeToString([]byte("test-key")) + "." +
				base64.RawURLEncoding.EncodeToString(make([]byte, nonceRandomSize)) +
				"." +
				strings.Repeat("|", base64.RawURLEncoding.EncodedLen(noncePayloadSize+nonceAEADTagSize)),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "decoding ciphertext failed")
			},
		},
		"fails on unknown key": {
			nonce: replaceNoncePart(t, validNonce, 0, base64.RawURLEncoding.EncodeToString([]byte("unknown-key"))),
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "key not found")
			},
		},
		"fails on tampered key id": {
			nonce: replaceNoncePart(t, validNonce, 0, base64.RawURLEncoding.EncodeToString([]byte("test-key-tampered"))),
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "key not found")
			},
		},
		"fails on tampered nonce": {
			nonce: tamperNoncePart(t, validNonce, 1),
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed to decrypt")
			},
		},
		"fails on tampered ciphertext": {
			nonce: tamperNoncePart(t, validNonce, 2),
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed to decrypt")
			},
		},
		"fails on binding mismatch": {
			nonce: validNonce,
			validateOpts: []ValidateOption{
				WithBinding([nonceBindingSize]byte{}),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "binding")
			},
		},
		"fails if nonce is too old": {
			nonce: validNonce,
			validateOpts: []ValidateOption{
				WithBinding(binding),
				WithMaxAge(1 * time.Nanosecond),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				time.Sleep(10 * time.Millisecond)

				require.Error(t, err)
				require.ErrorContains(t, err, "too old")
			},
		},
		"fails on unsupported payload version": {
			nonce: buildNonce(t, key, func() []byte {
				rawPayload := make([]byte, noncePayloadSize)
				rawPayload[0] = noncePayloadVersion + 1
				binary.BigEndian.PutUint64(rawPayload[1:9], uint64(time.Now().Unix())) //nolint: gosec
				copy(rawPayload[9:41], binding[:])

				return rawPayload
			}()),
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "unsupported payload version")
			},
		},
		"fails on bad issued at value": {
			nonce: buildNonce(t, key, func() []byte {
				rawPayload := make([]byte, noncePayloadSize)
				rawPayload[0] = noncePayloadVersion
				copy(rawPayload[9:41], binding[:])

				return rawPayload
			}()),
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "bad issued at value")
			},
		},
		"fails on nonce issued in the future": {
			nonce: buildNonce(t, key, func() []byte {
				rawPayload := make([]byte, noncePayloadSize)
				rawPayload[0] = noncePayloadVersion
				binary.BigEndian.PutUint64(rawPayload[1:9], uint64(time.Now().Add(time.Minute).Unix())) //nolint: gosec
				copy(rawPayload[9:41], binding[:])

				return rawPayload
			}()),
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "future")
			},
		},
		"succeeds": {
			nonce: validNonce,
			validateOpts: []ValidateOption{
				WithBinding(binding),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			err := ValidateNonce(tc.nonce, resolver, tc.validateOpts...)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestValidateNonceWithKeyAliases(t *testing.T) {
	t.Parallel()

	key := Key{
		KID:   "test-key",
		Value: []byte("0123456789abcdef0123456789abcdef"),
	}

	aliasKey := Key{
		KID:   "alias-key",
		Value: key.Value,
	}

	resolver := KeyResolverFunc(func(kid string) (Key, error) {
		switch kid {
		case key.KID:
			return key, nil
		case aliasKey.KID:
			return aliasKey, nil
		default:
			return Key{}, ErrNonceInvalid
		}
	})

	var binding [nonceBindingSize]byte
	copy(binding[:], []byte("test-binding"))

	validNonce, err := NewNonce(key, WithBinding(binding))
	require.NoError(t, err)

	aliasedNonce := replaceNoncePart(t, validNonce, 0, base64.RawURLEncoding.EncodeToString([]byte(aliasKey.KID)))

	// WHEN
	err = ValidateNonce(aliasedNonce, resolver, WithBinding(binding))

	// THEN
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to decrypt")
}

func tamperNoncePart(t *testing.T, nonce string, part int) string {
	t.Helper()

	parts := strings.Split(nonce, ".")
	require.Len(t, parts, 3)
	require.NotEmpty(t, parts[part])

	parts[part] = tamperString(parts[part])

	return strings.Join(parts, ".")
}

func replaceNoncePart(t *testing.T, nonce string, part int, value string) string {
	t.Helper()

	parts := strings.Split(nonce, ".")
	require.Len(t, parts, 3)

	parts[part] = value

	return strings.Join(parts, ".")
}

func tamperString(value string) string {
	if value[0] == 'A' {
		return "B" + value[1:]
	}

	return "A" + value[1:]
}

func buildNonce(t *testing.T, key Key, rawPayload []byte) string {
	t.Helper()

	var nonce [nonceRandomSize]byte
	copy(nonce[:], "01234567890123456789012345678901")

	aead, err := newCipher(key.Value, nonce[:])
	require.NoError(t, err)

	ciphertext := aead.Seal(nil, nonce[:nonceAEADNonceSize], rawPayload, []byte(key.KID))

	return base64.RawURLEncoding.EncodeToString([]byte(key.KID)) + "." +
		base64.RawURLEncoding.EncodeToString(nonce[:]) + "." +
		base64.RawURLEncoding.EncodeToString(ciphertext)
}
