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
	secret := NewStringSecret("inline", "foo", "bar")

	assert.Equal(t, "inline", secret.Source())
	assert.Equal(t, "foo", secret.Ref())
	assert.Equal(t, SecretKindString, secret.Kind())
	assert.Equal(t, "bar", secret.String())
}

func TestNewBytesSecret(t *testing.T) {
	secret := NewBytesSecret("file", "foo/bar", []byte("secret"))

	assert.Equal(t, "file", secret.Source())
	assert.Equal(t, "foo/bar", secret.Ref())
	assert.Equal(t, SecretKindBytes, secret.Kind())
	assert.Equal(t, []byte("secret"), secret.Bytes())
}

func TestNewSignerSecret(t *testing.T) {
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := &x509.Certificate{}
	secret := NewSignerSecret("pem", "first", "kid-1", signer, []*x509.Certificate{cert})

	assert.Equal(t, "pem", secret.Source())
	assert.Equal(t, "first", secret.Ref())
	assert.Equal(t, SecretKindSigner, secret.Kind())
	assert.Equal(t, "kid-1", secret.KeyID())
	assert.Same(t, crypto.Signer(signer), secret.Signer())
	assert.Equal(t, []*x509.Certificate{cert}, secret.CertChain())
}

func TestNewTrustStoreSecret(t *testing.T) {
	cert := &x509.Certificate{}
	secret := NewTrustStoreSecret("pem", "trust", []*x509.Certificate{cert})

	assert.Equal(t, "pem", secret.Source())
	assert.Equal(t, "trust", secret.Ref())
	assert.Equal(t, SecretKindTrustStore, secret.Kind())
	assert.NotNil(t, secret.CertPool())
}

func TestNewCredentials(t *testing.T) {
	secret := NewCredentials("inline", "foo", map[string]Secret{
		"username": NewStringSecret("inline", "foo/username", "foo"),
		"password": NewStringSecret("inline", "foo/password", "bar"),
	})

	assert.Equal(t, "inline", secret.Source())
	assert.Equal(t, "foo", secret.Ref())
}

func TestSecretPayloadDecode(t *testing.T) {
	for uc, tc := range map[string]struct {
		payload Credentials
		want    testCredentials
		wantErr bool
	}{
		"decodes string secrets": {
			payload: NewCredentials("inline", "foo", map[string]Secret{
				"username": NewStringSecret("inline", "foo/username", "foo"),
				"password": NewStringSecret("inline", "foo/password", "bar"),
			}),
			want: testCredentials{
				Username: "foo",
				Password: "bar",
			},
		},
		"decodes bytes secrets": {
			payload: NewCredentials("inline", "foo", map[string]Secret{
				"username_bytes": NewBytesSecret("inline", "foo/username_bytes", []byte("foo")),
				"password_bytes": NewBytesSecret("inline", "foo/password_bytes", []byte("bar")),
			}),
			want: testCredentials{
				UsernameBytes: []byte("foo"),
				PasswordBytes: []byte("bar"),
			},
		},
		"fails for unsupported secret kind": {
			payload: NewCredentials("inline", "foo", map[string]Secret{
				"username": NewStringSecret("inline", "foo/username", "foo"),
				"signer":   newTestSignerSecret(t),
			}),
			wantErr: true,
		},
		"fails on unused payload field": {
			payload: NewCredentials("inline", "foo", map[string]Secret{
				"username": NewStringSecret("inline", "foo/username", "foo"),
				"password": NewStringSecret("inline", "foo/password", "bar"),
				"extra":    NewStringSecret("inline", "foo/extra", "baz"),
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
		payload := NewCredentials("inline", "foo", map[string]Secret{
			"username": NewStringSecret("inline", "foo/username", "foo"),
		})

		err := payload.Decode(nil)

		require.Error(t, err)
	})
}

func TestSecretPayloadDecodeUnsupportedKindError(t *testing.T) {
	payload := NewCredentials("inline", "foo", map[string]Secret{
		"signer": newTestSignerSecret(t),
	})

	var out map[string]any

	err := payload.Decode(&out)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecretKindMismatch)
}

type testCredentials struct {
	Username      string `mapstructure:"username"`
	Password      string `mapstructure:"password"`
	UsernameBytes []byte `mapstructure:"username_bytes"`
	PasswordBytes []byte `mapstructure:"password_bytes"`
}

func newTestSignerSecret(t *testing.T) Secret {
	t.Helper()

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return NewSignerSecret("pem", "first", "kid-1", signer, nil)
}
