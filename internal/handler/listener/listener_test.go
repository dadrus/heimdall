// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package listener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/keyregistry"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNew(t *testing.T) {
	secret := newTLSSecret(t)
	address := "127.0.0.1:8443"

	for uc, tc := range map[string]struct {
		serviceConf config.ServeConfig
		setup       func(
			t *testing.T,
			sr *secretsmocks.ResolverMock,
			handle *secretsmocks.SecretHandleMock,
			ko *keyregistrymocks.KeyObserverMock,
		)
		listener  net.Listener
		listenErr error
		assert    func(t *testing.T, err error, ln net.Listener, base net.Listener, capturedAddress string)
	}{
		"creation fails": {
			serviceConf: config.ServeConfig{
				Host: ".....",
			},
			listenErr: assert.AnError,
			assert: func(t *testing.T, err error, _ net.Listener, _ net.Listener, capturedAddress string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, assert.AnError.Error())
				assert.Equal(t, address, capturedAddress)
			},
		},
		"without tls": {
			serviceConf: config.ServeConfig{Host: "127.0.0.1"},
			listener:    &acceptRecorder{},
			assert: func(t *testing.T, err error, ln net.Listener, base net.Listener, capturedAddress string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)
				assert.Equal(t, address, capturedAddress)

				wrapped, ok := ln.(*listener)
				require.True(t, ok)
				assert.Same(t, base, wrapped.Listener)
			},
		},
		"fails if secret cannot be resolved": {
			serviceConf: config.ServeConfig{
				TLS: &config.TLS{
					Secret: config.Secret{Source: "listener", Selector: "tls"},
				},
			},
			listener: &acceptRecorder{},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				_ *secretsmocks.SecretHandleMock,
				_ *keyregistrymocks.KeyObserverMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "listener", Selector: "tls"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(nil, assert.AnError)
			},
			assert: func(t *testing.T, err error, _ net.Listener, _ net.Listener, capturedAddress string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving TLS secret")
				assert.Equal(t, address, capturedAddress)
			},
		},
		"successful with secret backed tls config": {
			serviceConf: config.ServeConfig{
				TLS: &config.TLS{
					Secret:     config.Secret{Source: "listener", Selector: "tls"},
					MinVersion: tls.VersionTLS12,
				},
			},
			listener: &acceptRecorder{},
			setup: func(
				t *testing.T,
				sr *secretsmocks.ResolverMock,
				handle *secretsmocks.SecretHandleMock,
				ko *keyregistrymocks.KeyObserverMock,
			) {
				t.Helper()

				sr.EXPECT().
					Secret(
						mock.Anything,
						secrets.Reference{Source: "listener", Selector: "tls"},
						mock.AnythingOfType("secrets2.ResolveOption"),
					).
					Return(handle, nil)

				ko.EXPECT().
					Notify(mock.MatchedBy(func(ki keyregistry.KeyInfo) bool {
						return ki.Key.KeyID() == secret.KeyID() &&
							ki.Key.PrivateKey() == secret.PrivateKey() &&
							assert.ObjectsAreEqual(ki.Key.CertChain(), secret.CertChain()) &&
							!ki.Exportable
					})).
					Return()

				handle.EXPECT().
					OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
						err := cb(context.Background(), secret)
						require.NoError(t, err)

						return true
					}))
			},
			assert: func(t *testing.T, err error, ln net.Listener, base net.Listener, capturedAddress string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)
				assert.Equal(t, address, capturedAddress)
				assert.NotSame(t, base, ln)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			prevListen := listen

			var capturedAddress string

			t.Cleanup(func() { listen = prevListen })

			listen = func(_ context.Context, currentAddress string) (net.Listener, error) {
				capturedAddress = currentAddress

				if tc.listenErr != nil {
					return nil, tc.listenErr
				}

				return tc.listener, nil
			}

			sr := secretsmocks.NewResolverMock(t)
			handle := secretsmocks.NewSecretHandleMock(t)
			ko := keyregistrymocks.NewKeyObserverMock(t)

			if tc.setup != nil {
				tc.setup(t, sr, handle, ko)
			}

			ln, err := New(t.Context(), address, tc.serviceConf.TLS, sr, ko)

			defer func() {
				if ln != nil {
					_ = ln.Close()
				}
			}()

			tc.assert(t, err, ln, tc.listener, capturedAddress)
		})
	}
}

func TestListenerAccept(t *testing.T) {
	expectedConn := &connRecorder{}
	expectedErr := assert.AnError

	tests := map[string]struct {
		listener net.Listener
		assert   func(t *testing.T, accepted net.Conn, err error)
	}{
		"wraps accepted connection": {
			listener: &acceptRecorder{conn: expectedConn},
			assert: func(t *testing.T, accepted net.Conn, err error) {
				t.Helper()

				require.NoError(t, err)

				wrapped, ok := accepted.(*conn)
				require.True(t, ok)
				assert.Same(t, expectedConn, wrapped.Conn)
			},
		},
		"returns accept error": {
			listener: &acceptRecorder{err: expectedErr},
			assert: func(t *testing.T, accepted net.Conn, err error) {
				t.Helper()

				require.ErrorIs(t, err, expectedErr)
				assert.Nil(t, accepted)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			conn, err := (&listener{Listener: tc.listener}).Accept()

			tc.assert(t, conn, err)
		})
	}
}

type acceptRecorder struct {
	conn net.Conn
	err  error
}

func (r *acceptRecorder) Accept() (net.Conn, error) { return r.conn, r.err }
func (r *acceptRecorder) Close() error              { return nil }
func (r *acceptRecorder) Addr() net.Addr            { return &net.TCPAddr{} }

func newTLSSecret(t *testing.T) secrets.AsymmetricKeySecret {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(
		testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey),
	).Build()
	require.NoError(t, err)

	return types.NewAsymmetricKeySecret("tls", "key1", privKey, []*x509.Certificate{cert})
}
