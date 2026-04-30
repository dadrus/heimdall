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

package types_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/secrets/types"
)

func TestSecretAsString(t *testing.T) {
	sec := types.Secret{
		Type:  types.SecretTypePlain,
		Value: "foo",
	}

	value, err := sec.AsString()
	require.NoError(t, err)
	require.Equal(t, "foo", value)
}

func TestSecretAsBytes(t *testing.T) {
	sec := types.Secret{
		Type:  types.SecretTypeSymmetric,
		Value: []byte("foo"),
	}

	value, err := sec.AsBytes()
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), value)
}

func TestSecretAsSigner(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sec := types.Secret{
		Type:  types.SecretTypeAsymmetric,
		Value: crypto.Signer(privateKey),
	}

	value, err := sec.AsSigner()
	require.NoError(t, err)
	require.Equal(t, privateKey, value)
}

func TestSecretAsTypeMismatch(t *testing.T) {
	sec := types.Secret{
		Type:  types.SecretTypePlain,
		Value: "foo",
	}

	_, err := sec.AsBytes()
	require.Error(t, err)
	require.ErrorIs(t, err, types.ErrSecretTypeMismatch)
}
