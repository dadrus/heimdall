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

package finalizers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	mocks3 "github.com/dadrus/heimdall/internal/keyholder/mocks"
	mocks4 "github.com/dadrus/heimdall/internal/otel/metrics/certificate/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	mocks2 "github.com/dadrus/heimdall/internal/watcher/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pkix/pemx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateJWTFinalizer(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey, pemx.WithHeader("X-Key-ID", "key")),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	pemFile := filepath.Join(testDir, "keystore.pem")

	err = os.WriteFile(pemFile, pemBytes, 0644)
	require.NoError(t, err)

	const expectedTTL = 5 * time.Second

	for _, tc := range []struct {
		uc               string
		id               string
		config           []byte
		configureContext func(t *testing.T, ctx *CreationContextMock)
		assert           func(t *testing.T, err error, finalizer *jwtFinalizer)
	}{
		{
			uc:               "without config",
			id:               "fin",
			configureContext: func(t *testing.T, _ *CreationContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'signer' is a required field")
			},
		},
		{
			uc:               "with empty config",
			id:               "fin",
			config:           []byte(``),
			configureContext: func(t *testing.T, _ *CreationContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'signer' is a required field")
			},
		},
		{
			uc: "with signer only",
			id: "fin",
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
  key_id: key
`),
			configureContext: func(t *testing.T, ctx *CreationContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().Add(mock.Anything)

				co := mocks4.NewObserverMock(t)
				co.EXPECT().Add(mock.Anything)

				ctx.EXPECT().Watcher().Return(wm)
				ctx.EXPECT().KeyHolderRegistry().Return(khr)
				ctx.EXPECT().CertificateObserver().Return(co)
			},
			assert: func(t *testing.T, err error, finalizer *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, finalizer)
				assert.Equal(t, defaultJWTTTL, finalizer.ttl)
				assert.Nil(t, finalizer.claims)
				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, "key", finalizer.signer.keyID)
				assert.Equal(t, privKey, finalizer.signer.key)
			},
		},
		{
			uc: "with ttl and signer",
			id: "fin",
			config: []byte(`
ttl: 5s
signer:
  name: foo
  key_store: 
    path: ` + pemFile + `
`),
			configureContext: func(t *testing.T, ctx *CreationContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().Add(mock.Anything)

				co := mocks4.NewObserverMock(t)
				co.EXPECT().Add(mock.Anything)

				ctx.EXPECT().Watcher().Return(wm)
				ctx.EXPECT().KeyHolderRegistry().Return(khr)
				ctx.EXPECT().CertificateObserver().Return(co)
			},
			assert: func(t *testing.T, err error, finalizer *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, finalizer)
				assert.Equal(t, expectedTTL, finalizer.ttl)
				assert.Nil(t, finalizer.claims)
				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "foo", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
			},
		},
		{
			uc: "with too short ttl",
			config: []byte(`
ttl: 5ms
signer:
  key_store: 
    path: ` + pemFile + `
`),
			configureContext: func(t *testing.T, _ *CreationContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'ttl' must be greater than 1s")
			},
		},
		{
			uc: "with claims and key store",
			id: "fin",
			config: []byte(`
signer:
  name: foo
  key_store: 
    path: ` + pemFile + `
claims: 
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			configureContext: func(t *testing.T, ctx *CreationContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().Add(mock.Anything)

				co := mocks4.NewObserverMock(t)
				co.EXPECT().Add(mock.Anything)

				ctx.EXPECT().Watcher().Return(wm)
				ctx.EXPECT().KeyHolderRegistry().Return(khr)
				ctx.EXPECT().CertificateObserver().Return(co)
			},
			assert: func(t *testing.T, err error, finalizer *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, finalizer)
				assert.Equal(t, defaultJWTTTL, finalizer.ttl)
				require.NotNil(t, finalizer.claims)
				val, err := finalizer.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				assert.False(t, finalizer.ContinueOnError())
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "foo", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
			},
		},
		{
			uc: "with claims, signer and ttl",
			id: "fin",
			config: []byte(`
ttl: 5s
signer:
  key_store: 
    path: ` + pemFile + `
claims: 
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			configureContext: func(t *testing.T, ctx *CreationContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().Add(mock.Anything)

				co := mocks4.NewObserverMock(t)
				co.EXPECT().Add(mock.Anything)

				ctx.EXPECT().Watcher().Return(wm)
				ctx.EXPECT().KeyHolderRegistry().Return(khr)
				ctx.EXPECT().CertificateObserver().Return(co)
			},
			assert: func(t *testing.T, err error, finalizer *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, finalizer)
				assert.Equal(t, expectedTTL, finalizer.ttl)
				require.NotNil(t, finalizer.claims)
				val, err := finalizer.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				assert.False(t, finalizer.ContinueOnError())
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
			},
		},
		{
			uc: "with unknown entries in configuration",
			config: []byte(`
ttl: 5s
foo: bar"
`),
			configureContext: func(t *testing.T, _ *CreationContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		{
			uc: "with bad header config",
			config: []byte(`
signer:
  key_store: 
    path: ` + pemFile + `
header:
  scheme: Foo
`),
			configureContext: func(t *testing.T, _ *CreationContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'header'.'name' is a required field")
			},
		},
		{
			uc: "with valid header config without scheme",
			id: "fin",
			config: []byte(`
signer:
  key_store: 
    path: ` + pemFile + `
header:
  name: Foo
`),
			configureContext: func(t *testing.T, ctx *CreationContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().Add(mock.Anything)

				co := mocks4.NewObserverMock(t)
				co.EXPECT().Add(mock.Anything)

				ctx.EXPECT().Watcher().Return(wm)
				ctx.EXPECT().KeyHolderRegistry().Return(khr)
				ctx.EXPECT().CertificateObserver().Return(co)
			},
			assert: func(t *testing.T, err error, finalizer *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)
				assert.Equal(t, defaultJWTTTL, finalizer.ttl)
				assert.Nil(t, finalizer.claims)
				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "Foo", finalizer.headerName)
				assert.Empty(t, finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
			},
		},
		{
			uc: "with valid header config with scheme",
			id: "fin",
			config: []byte(`
signer:
  key_store: 
    path: ` + pemFile + `
header:
  name: Foo
  scheme: Bar
`),
			configureContext: func(t *testing.T, ctx *CreationContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().Add(mock.Anything)

				co := mocks4.NewObserverMock(t)
				co.EXPECT().Add(mock.Anything)

				ctx.EXPECT().Watcher().Return(wm)
				ctx.EXPECT().KeyHolderRegistry().Return(khr)
				ctx.EXPECT().CertificateObserver().Return(co)
			},
			assert: func(t *testing.T, err error, finalizer *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, finalizer)
				assert.Equal(t, defaultJWTTTL, finalizer.ttl)
				assert.Nil(t, finalizer.claims)
				assert.Equal(t, "fin", finalizer.ID())
				assert.Equal(t, "Foo", finalizer.headerName)
				assert.Equal(t, "Bar", finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			ctx := NewCreationContextMock(t)
			tc.configureContext(t, ctx)

			// WHEN
			finalizer, err := newJWTFinalizer(ctx, tc.id, conf)

			// THEN
			tc.assert(t, err, finalizer)
		})
	}
}

func TestCreateJWTFinalizerFromPrototype(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey, pemx.WithHeader("X-Key-ID", "key")),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	pemFile := filepath.Join(testDir, "keystore.pem")

	err = os.WriteFile(pemFile, pemBytes, 0640)
	require.NoError(t, err)

	const expectedTTL = 5 * time.Second

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer)
	}{
		{
			uc: "no new configuration provided",
			id: "fin1",
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "fin1", configured.ID())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc: "empty configuration provided",
			id: "fin2",
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "fin2", configured.ID())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc: "configuration with ttl only provided",
			id: "fin3",
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			config: []byte(`ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.claims, configured.claims)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.Equal(t, "fin3", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		{
			uc: "configuration with too short ttl",
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			config: []byte(`ttl: 5ms`),
			assert: func(t *testing.T, err error, _ *jwtFinalizer, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'ttl' must be greater than 1s")
			},
		},
		{
			uc: "configuration with claims only provided",
			id: "fin4",
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			config: []byte(`
claims:
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				val, err := configured.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "fin4", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		{
			uc: "configuration with both ttl and claims provided",
			id: "fin5",
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			config: []byte(`
ttl: 5s
claims:
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				val, err := configured.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "fin5", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		{
			uc: "with unknown entries in configuration",
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			config: []byte(`
ttl: 5s
foo: bar
`),
			assert: func(t *testing.T, err error, _ *jwtFinalizer, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			protoConf, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			wm := mocks2.NewWatcherMock(t)
			wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

			khr := mocks3.NewRegistryMock(t)
			khr.EXPECT().Add(mock.Anything)

			co := mocks4.NewObserverMock(t)
			co.EXPECT().Add(mock.Anything)

			ctx := NewCreationContextMock(t)
			ctx.EXPECT().Watcher().Return(wm)
			ctx.EXPECT().KeyHolderRegistry().Return(khr)
			ctx.EXPECT().CertificateObserver().Return(co)

			prototype, err := newJWTFinalizer(ctx, tc.id, protoConf)
			require.NoError(t, err)

			// WHEN
			finalizer, err := prototype.WithConfig(conf)

			// THEN
			var (
				jwtFin *jwtFinalizer
				ok     bool
			)

			if err == nil {
				jwtFin, ok = finalizer.(*jwtFinalizer)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, jwtFin)
		})
	}
}

func TestJWTFinalizerExecute(t *testing.T) {
	t.Parallel()

	const configuredTTL = 1 * time.Minute

	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := pemx.BuildPEM(
		pemx.WithECDSAPrivateKey(privKey, pemx.WithHeader("X-Key-ID", "key")),
	)
	require.NoError(t, err)

	testDir := t.TempDir()
	pemFile := filepath.Join(testDir, "keystore.pem")

	err = os.WriteFile(pemFile, pemBytes, 0644)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc             string
		id             string
		config         []byte
		subject        *subject.Subject
		configureMocks func(t *testing.T,
			fin *jwtFinalizer,
			ctx *heimdallmocks.ContextMock,
			cch *mocks.CacheMock,
			sub *subject.Subject)
		assert func(t *testing.T, err error)
	}{
		{
			uc: "with 'nil' subject",
			id: "fin1",
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "fin1", identifier.ID())
			},
		},
		{
			uc: "with used prefilled cache",
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, fin *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer TestToken")
				ctx.EXPECT().Outputs().Return(heimdall.Outputs{"foo": "bar"})

				cacheKey := fin.calculateCacheKey(ctx, sub)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return([]byte("TestToken"), nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "with no cache hit and without custom claims",
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
ttl: 1m
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
				ctx.EXPECT().Outputs().Return(heimdall.Outputs{})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, configuredTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "with no cache hit, with custom claims and custom header",
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
header:
  name: X-Token
  scheme: Bar
claims: '{
  {{ $val := .Subject.Attributes.baz }}
  "sub_id": {{ quote .Subject.ID }}, 
  {{ quote $val }}: "baz",
  "foo": {{ .Outputs.foo | quote }}
}'`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("X-Token",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bar ") }))
				ctx.EXPECT().Outputs().Return(heimdall.Outputs{"foo": "bar"})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, defaultJWTTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "with custom claims template, which does not result in a JSON object",
			id: "jun2",
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
claims: "foo: bar"
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(heimdall.Outputs{})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to unmarshal claims")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "jun2", identifier.ID())
			},
		},
		{
			uc: "with custom claims template, which fails during rendering",
			id: "jun3",
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
claims: "{{ len .foobar }}"
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.ContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(heimdall.Outputs{})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "jun3", identifier.ID())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *jwtFinalizer, _ *heimdallmocks.ContextMock, _ *mocks.CacheMock, _ *subject.Subject) {
					t.Helper()
				})

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			cch := mocks.NewCacheMock(t)
			mctx := heimdallmocks.NewContextMock(t)

			wm := mocks2.NewWatcherMock(t)
			wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

			khr := mocks3.NewRegistryMock(t)
			khr.EXPECT().Add(mock.Anything)

			co := mocks4.NewObserverMock(t)
			co.EXPECT().Add(mock.Anything)

			cctx := NewCreationContextMock(t)
			cctx.EXPECT().Watcher().Return(wm)
			cctx.EXPECT().KeyHolderRegistry().Return(khr)
			cctx.EXPECT().CertificateObserver().Return(co)

			mctx.EXPECT().AppContext().Return(cache.WithContext(context.Background(), cch))

			finalizer, err := newJWTFinalizer(cctx, tc.id, conf)
			require.NoError(t, err)

			configureMocks(t, finalizer, mctx, cch, tc.subject)

			// WHEN
			err = finalizer.Execute(mctx, tc.subject)

			// THEN
			tc.assert(t, err)
		})
	}
}
