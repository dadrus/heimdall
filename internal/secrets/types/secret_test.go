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

package types //nolint:revive

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStringSecret(t *testing.T) {
	secret := NewStringSecret("foo", "bar")

	assert.Equal(t, "foo", secret.Selector())
	assert.Equal(t, SecretKindString, secret.Kind())
	assert.Equal(t, "bar", secret.Value())
}

func TestNewBytesSecret(t *testing.T) {
	secret := NewSymmetricKeySecret("foo/bar", "bar", []byte("secret"))

	assert.Equal(t, "foo/bar", secret.Selector())
	assert.Equal(t, "bar", secret.KeyID())
	assert.Equal(t, SecretKindSymmetricKey, secret.Kind())
	assert.Equal(t, []byte("secret"), secret.Key())
}

func TestNewSignerSecret(t *testing.T) {
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &x509.Certificate{}
	secret := NewAsymmetricKeySecret("first", "kid-1", signer, []*x509.Certificate{cert})

	assert.Equal(t, "first", secret.Selector())
	assert.Equal(t, SecretKindAsymmetricKey, secret.Kind())
	assert.Equal(t, "kid-1", secret.KeyID())
	assert.Same(t, crypto.Signer(signer), secret.PrivateKey())
	assert.Equal(t, []*x509.Certificate{cert}, secret.CertChain())
}

func TestNewTrustStoreSecret(t *testing.T) {
	cert := &x509.Certificate{}
	secret := NewTrustStoreSecret("trust", []*x509.Certificate{cert})

	assert.Equal(t, "trust", secret.Selector())
	assert.Equal(t, SecretKindTrustStore, secret.Kind())
	assert.NotNil(t, secret.CertPool())
}

func TestNewCredentials(t *testing.T) {
	secret := NewCredentials("foo", map[string]any{
		"username": "foo",
		"password": "bar",
	})

	assert.Equal(t, "foo", secret.Selector())
}

func TestSecretPayloadDecode(t *testing.T) {
	type testCredentials struct {
		Username string `mapstructure:"username"`
		Password string `mapstructure:"password"`
	}

	for uc, tc := range map[string]struct {
		payload Credentials
		want    testCredentials
		wantErr bool
	}{
		"decodes string secrets": {
			payload: NewCredentials("foo", map[string]any{
				"username": "foo",
				"password": "bar",
			}),
			want: testCredentials{
				Username: "foo",
				Password: "bar",
			},
		},
		"fails on unused payload field": {
			payload: NewCredentials("foo", map[string]any{
				"username": "foo",
				"password": "bar",
				"extra":    "baz",
			}),
			wantErr: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			var got testCredentials

			err := tc.payload.Decode(&got)

			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("fails creating decoder", func(t *testing.T) {
		payload := NewCredentials("foo", map[string]any{
			"username": "foo",
		})

		err := payload.Decode(nil)

		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidCredentialsPayload)
	})
}
