package nonce

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkNewNonce(b *testing.B) {
	key := Key{
		KID:   "test-key",
		Value: []byte("0123456789abcdef0123456789abcdef"),
	}

	var binding [nonceBindingSize]byte
	copy(binding[:], "test-binding")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, err := NewNonce(key, WithBinding(binding))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateNonce(b *testing.B) {
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
	copy(binding[:], "test-binding")

	nonce, err := NewNonce(key, WithBinding(binding))
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		err := ValidateNonce(nonce, resolver, WithBinding(binding))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewNonceAndValidateNonce(b *testing.B) {
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
	copy(binding[:], "test-binding")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		nonce, err := NewNonce(key, WithBinding(binding))
		if err != nil {
			b.Fatal(err)
		}

		err = ValidateNonce(nonce, resolver, WithBinding(binding))
		if err != nil {
			b.Fatal(err)
		}
	}
}
