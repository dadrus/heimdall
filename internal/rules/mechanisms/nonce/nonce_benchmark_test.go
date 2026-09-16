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
