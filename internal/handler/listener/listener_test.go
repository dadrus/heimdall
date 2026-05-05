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
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	keyregistry "github.com/dadrus/heimdall/internal/keyregistry/v2"
	keyregistrymocks "github.com/dadrus/heimdall/internal/keyregistry/v2/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNew(t *testing.T) {
	secret := newTLSSecret(t)

	tests := map[string]struct {
		serviceConf config.ServeConfig
		setupMocks  func(t *testing.T) (secrets.Manager, keyregistry.KeyObserver, func())
		listener    net.Listener
		listenErr   error
		assert      func(t *testing.T, err error, ln net.Listener, port string)
	}{
		"creation fails": {
			serviceConf: config.ServeConfig{
				Host: ".....",
			},
			listenErr: errors.New("no such host"),
			assert: func(t *testing.T, err error, _ net.Listener, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "no such host")
			},
		},
		"without tls": {
			serviceConf: config.ServeConfig{Host: "127.0.0.1"},
			listener:    newStaticListener(),
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)
				assert.Equal(t, "tcp", ln.Addr().Network())
				assert.Equal(t, "127.0.0.1:"+port, ln.Addr().String())
			},
		},
		"fails if secret cannot be resolved": {
			serviceConf: config.ServeConfig{
				TLS: &config.TLS{
					Secret: config.Secret{Source: "listener", Selector: "tls"},
				},
			},
			listener: newStaticListener(),
			setupMocks: func(t *testing.T) (secrets.Manager, keyregistry.KeyObserver, func()) {
				t.Helper()

				sm := secretsmocks.NewManagerMock(t)
				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("listener", "tls")).
					Return(nil, errors.New("boom"))

				return sm, nil, func() {}
			},
			assert: func(t *testing.T, err error, _ net.Listener, _ string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed resolving TLS secret")
			},
		},
		"successful with secret backed tls config": {
			serviceConf: config.ServeConfig{
				TLS: &config.TLS{
					Secret:     config.Secret{Source: "listener", Selector: "tls"},
					MinVersion: tls.VersionTLS12,
				},
			},
			listener: newStaticListener(),
			setupMocks: func(t *testing.T) (secrets.Manager, keyregistry.KeyObserver, func()) {
				t.Helper()

				sm := secretsmocks.NewManagerMock(t)
				ko := keyregistrymocks.NewKeyObserverMock(t)

				ko.EXPECT().
					Notify(mock.MatchedBy(func(ki keyregistry.KeyInfo) bool {
						return ki.Key.KeyID() == secret.KeyID() &&
							ki.Key.PrivateKey() == secret.PrivateKey() &&
							assert.ObjectsAreEqual(ki.Key.CertChain(), secret.CertChain()) &&
							!ki.Exportable
					})).
					Return()

				sm.EXPECT().
					ResolveSecret(mock.Anything, secrets.InternalRef("listener", "tls")).
					Return(secret, nil)
				sm.EXPECT().
					Subscribe(secrets.InternalRef("listener", "tls"), mock.Anything).
					Return(func() {}, nil)

				return sm, ko, func() {}
			},
			assert: func(t *testing.T, err error, ln net.Listener, port string) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ln)
				assert.Equal(t, "tcp", ln.Addr().Network())
				assert.Contains(t, ln.Addr().String(), port)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			prevListen := listen

			t.Cleanup(func() { listen = prevListen })

			listen = func(_ context.Context, _ string) (net.Listener, error) {
				if tc.listenErr != nil {
					return nil, tc.listenErr
				}

				return tc.listener, nil
			}

			var (
				sm      secrets.Manager
				ko      keyregistry.KeyObserver
				cleanup = func() {}
			)

			if tc.setupMocks != nil {
				sm, ko, cleanup = tc.setupMocks(t)
			}

			port := "8443"
			ln, err := New(t.Context(), "127.0.0.1:"+port, tc.serviceConf.TLS, sm, ko)

			defer func() {
				cleanup()

				if ln != nil {
					ln.Close()
				}
			}()

			tc.assert(t, err, ln, port)
		})
	}
}


func TestListenerAccept(t *testing.T) {
	expectedConn := &connRecorder{}
	expectedErr := errors.New("boom")

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


type staticListener struct {
	addr net.Addr
}

func newStaticListener() net.Listener {
	return &staticListener{
		addr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 8443,
		},
	}
}

func (l *staticListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (l *staticListener) Close() error              { return nil }
func (l *staticListener) Addr() net.Addr            { return l.addr }

func newTLSSecret(t *testing.T) secrets.AsymmetricKeySecret {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cert, err := testsupport.NewCertificateBuilder(testsupport.WithValidity(time.Now(), 10*time.Hour),
		testsupport.WithSerialNumber(big.NewInt(1)),
		testsupport.WithSubject(pkix.Name{
			CommonName:   "test cert",
			Organization: []string{"Test"},
			Country:      []string{"EU"},
		}),
		testsupport.WithSubjectPubKey(&privKey.PublicKey, x509.ECDSAWithSHA384),
		testsupport.WithSelfSigned(),
		testsupport.WithSignaturePrivKey(privKey)).
		Build()
	require.NoError(t, err)

	return secrettypes.NewAsymmetricKeySecret("listener", "tls", "key1", privKey, []*x509.Certificate{cert})
}
