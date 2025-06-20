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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	mocks3 "github.com/dadrus/heimdall/internal/keyholder/mocks"
	mocks4 "github.com/dadrus/heimdall/internal/otel/metrics/certificate/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/validation"
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

	err = os.WriteFile(pemFile, pemBytes, 0o600)
	require.NoError(t, err)

	const expectedTTL = 5 * time.Second

	for uc, tc := range map[string]struct {
		config              []byte
		configureAppContext func(t *testing.T, ctx *app.ContextMock)
		assert              func(t *testing.T, err error, finalizer *jwtFinalizer)
	}{
		"without config": {
			configureAppContext: func(t *testing.T, _ *app.ContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'signer' is a required field")
			},
		},
		"with empty config": {
			config:              []byte(``),
			configureAppContext: func(t *testing.T, _ *app.ContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "'signer' is a required field")
			},
		},
		"with not existing key store for signer": {
			config: []byte(`
signer:
  key_store:
    path: /does/not/exist.pem
  key_id: key
`),
			configureAppContext: func(t *testing.T, ctx *app.ContextMock) {
				t.Helper()

				ctx.EXPECT().Watcher().Return(mocks2.NewWatcherMock(t))
			},
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "failed loading keystore")
			},
		},
		"with signer only": {
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
  key_id: key
`),
			configureAppContext: func(t *testing.T, ctx *app.ContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().AddKeyHolder(mock.Anything)

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
				assert.Equal(t, "with signer only", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, "key", finalizer.signer.keyID)
				assert.Equal(t, privKey, finalizer.signer.key)
				assert.Empty(t, finalizer.Certificates())
			},
		},
		"with ttl and signer": {
			config: []byte(`
ttl: 5s
signer:
  name: foo
  key_store: 
    path: ` + pemFile + `
`),
			configureAppContext: func(t *testing.T, ctx *app.ContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().AddKeyHolder(mock.Anything)

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
				assert.Equal(t, "with ttl and signer", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "foo", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
				assert.Empty(t, finalizer.Certificates())
			},
		},
		"with too short ttl": {
			config: []byte(`
ttl: 5ms
signer:
  key_store: 
    path: ` + pemFile + `
`),
			configureAppContext: func(t *testing.T, _ *app.ContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'ttl' must be greater than 1s")
			},
		},
		"with claims and key store": {
			config: []byte(`
signer:
  name: foo
  key_store: 
    path: ` + pemFile + `
claims: 
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			configureAppContext: func(t *testing.T, ctx *app.ContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().AddKeyHolder(mock.Anything)

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
				assert.JSONEq(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "with claims and key store", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				assert.False(t, finalizer.ContinueOnError())
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "foo", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
				assert.Empty(t, finalizer.Certificates())
			},
		},
		"with claims, signer and ttl": {
			config: []byte(`
ttl: 5s
signer:
  key_store: 
    path: ` + pemFile + `
claims: '{ "sub": {{ quote .Subject.ID }} }'
`),
			configureAppContext: func(t *testing.T, ctx *app.ContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().AddKeyHolder(mock.Anything)

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
				assert.JSONEq(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "with claims, signer and ttl", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, "Authorization", finalizer.headerName)
				assert.Equal(t, "Bearer", finalizer.headerScheme)
				assert.False(t, finalizer.ContinueOnError())
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
				assert.Empty(t, finalizer.Certificates())
			},
		},
		"with unknown entries in configuration": {
			config: []byte(`
ttl: 5s
foo: bar"
`),
			configureAppContext: func(t *testing.T, _ *app.ContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
		"with bad header config": {
			config: []byte(`
signer:
  key_store: 
    path: ` + pemFile + `
header:
  scheme: Foo
`),
			configureAppContext: func(t *testing.T, _ *app.ContextMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ *jwtFinalizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "'header'.'name' is a required field")
			},
		},
		"with valid header config without scheme": {
			config: []byte(`
signer:
  key_store: 
    path: ` + pemFile + `
header:
  name: Foo
`),
			configureAppContext: func(t *testing.T, ctx *app.ContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().AddKeyHolder(mock.Anything)

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
				assert.Equal(t, "with valid header config without scheme", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, "Foo", finalizer.headerName)
				assert.Empty(t, finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
				assert.Empty(t, finalizer.Certificates())
			},
		},
		"with all possible entries": {
			config: []byte(`
ttl: 1m
signer:
  key_store: 
    path: ` + pemFile + `
header:
  name: Foo
  scheme: Bar
claims: '{{ .Values.foo }}'
values:
  foo: '{{ .Subject.ID }}'
`),
			configureAppContext: func(t *testing.T, ctx *app.ContextMock) {
				t.Helper()

				wm := mocks2.NewWatcherMock(t)
				wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

				khr := mocks3.NewRegistryMock(t)
				khr.EXPECT().AddKeyHolder(mock.Anything)

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
				assert.Equal(t, time.Minute, finalizer.ttl)
				assert.NotNil(t, finalizer.claims)
				assert.Equal(t, "with all possible entries", finalizer.ID())
				assert.Equal(t, finalizer.Name(), finalizer.ID())
				assert.Equal(t, "Foo", finalizer.headerName)
				assert.Equal(t, "Bar", finalizer.headerScheme)
				require.NotNil(t, finalizer.signer)
				assert.Equal(t, "heimdall", finalizer.signer.iss)
				assert.Equal(t, pemFile, finalizer.signer.path)
				assert.Equal(t, privKey, finalizer.signer.key)
				assert.Len(t, finalizer.v, 1)
				assert.Empty(t, finalizer.Certificates())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			tc.configureAppContext(t, appCtx)

			// WHEN
			finalizer, err := newJWTFinalizer(appCtx, uc, conf)

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

	err = os.WriteFile(pemFile, pemBytes, 0o600)
	require.NoError(t, err)

	const expectedTTL = 5 * time.Second

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer)
	}{
		"no new configuration provided": {
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration provided", configured.ID())
				assert.False(t, configured.ContinueOnError())
			},
		},
		"empty configuration provided": {
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
				assert.Equal(t, "empty configuration provided", configured.ID())
				assert.False(t, configured.ContinueOnError())
			},
		},
		"configuration with ttl only provided": {
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
				assert.Equal(t, "configuration with ttl only provided", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		"configuration with too short ttl": {
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
		"configuration with claims only provided": {
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
				assert.JSONEq(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "configuration with claims only provided", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		"configuration with claims and values": {
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			config: []byte(`
claims: '{ "sub": {{ quote .Value.foo }} }'
values:
  foo: '{{ quote .Subject.ID }}'
`),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, defaultJWTTTL, configured.ttl)
				assert.Nil(t, prototype.claims)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				assert.Equal(t, "configuration with claims and values", configured.ID())
				assert.NotEmpty(t, configured.v)
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		"configuration with both ttl and claims provided": {
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
				assert.JSONEq(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "configuration with both ttl and claims provided", configured.ID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		"configuration with values": {
			prototypeConfig: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
claims: '{ "foo": {{ quote .Values.foo }} }'
values:
  foo: bar
`),
			config: []byte(`
values:
  foo: '{{ quote .Subject.ID }}'
`),
			assert: func(t *testing.T, err error, prototype *jwtFinalizer, configured *jwtFinalizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, "Authorization", configured.headerName)
				assert.Equal(t, "Bearer", configured.headerScheme)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.Equal(t, defaultJWTTTL, configured.ttl)
				assert.Equal(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				assert.Equal(t, "configuration with values", configured.ID())
				assert.NotEmpty(t, configured.v)
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
				assert.Equal(t, prototype.signer, configured.signer)
			},
		},
		"with unknown entries in configuration": {
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
		t.Run(uc, func(t *testing.T) {
			protoConf, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			wm := mocks2.NewWatcherMock(t)
			wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

			khr := mocks3.NewRegistryMock(t)
			khr.EXPECT().AddKeyHolder(mock.Anything)

			co := mocks4.NewObserverMock(t)
			co.EXPECT().Add(mock.Anything)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Watcher().Return(wm)
			appCtx.EXPECT().KeyHolderRegistry().Return(khr)
			appCtx.EXPECT().CertificateObserver().Return(co)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prototype, err := newJWTFinalizer(appCtx, uc, protoConf)
			require.NoError(t, err)

			// WHEN
			finalizer, err := prototype.WithConfig("", conf)

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

	err = os.WriteFile(pemFile, pemBytes, 0o600)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		config         []byte
		subject        *subject.Subject
		configureMocks func(t *testing.T,
			fin *jwtFinalizer,
			ctx *heimdallmocks.RequestContextMock,
			cch *mocks.CacheMock,
			sub *subject.Subject)
		assert func(t *testing.T, err error)
	}{
		"with 'nil' subject": {
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
				assert.Equal(t, "with 'nil' subject", identifier.ID())
			},
		},
		"with used prefilled cache": {
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, fin *jwtFinalizer, ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer TestToken")
				ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})

				cacheKey := fin.calculateCacheKey(ctx, sub)
				cch.EXPECT().Get(mock.Anything, cacheKey).Return([]byte("TestToken"), nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no cache hit and without custom claims": {
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
ttl: 1m
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
				ctx.EXPECT().Outputs().Return(map[string]any{})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, configuredTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no cache hit, with custom claims and custom header": {
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
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("X-Token",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bar ") }))
				ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, defaultJWTTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with no cache hit, with custom claims and values": {
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
claims: '{{- dict "foo" .Values.foo "bar" .Values.bar | toJson -}}'
values:
  foo: '{{ .Subject.ID | quote }}'
  bar: '{{ .Outputs.bar | quote }}'
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().AddHeaderForUpstream("Authorization",
					mock.MatchedBy(func(val string) bool { return strings.HasPrefix(val, "Bearer ") }))
				ctx.EXPECT().Outputs().Return(map[string]any{"bar": "baz"})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
				cch.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, defaultJWTTTL-defaultCacheLeeway).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"with custom claims template, which does not result in a JSON object": {
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
claims: "foo: bar"
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to unmarshal claims")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with custom claims template, which does not result in a JSON object", identifier.ID())
			},
		},
		"with custom claims template, which fails during rendering": {
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
claims: "{{ len .foobar }}"
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render claims")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with custom claims template, which fails during rendering", identifier.ID())
			},
		},
		"with values template, which fails during rendering": {
			config: []byte(`
signer:
  key_store:
    path: ` + pemFile + `
claims: "{{ quote .Values.foo }}"
values:
  foo: '{{ len .fooo }}'
`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, _ *jwtFinalizer, ctx *heimdallmocks.RequestContextMock,
				cch *mocks.CacheMock, _ *subject.Subject,
			) {
				t.Helper()

				ctx.EXPECT().Outputs().Return(map[string]any{})

				cch.EXPECT().Get(mock.Anything, mock.Anything).Return(nil, errors.New("no cache entry"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render values")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "with values template, which fails during rendering", identifier.ID())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *jwtFinalizer, _ *heimdallmocks.RequestContextMock, _ *mocks.CacheMock, _ *subject.Subject) {
					t.Helper()
				})

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			cch := mocks.NewCacheMock(t)
			mctx := heimdallmocks.NewRequestContextMock(t)

			wm := mocks2.NewWatcherMock(t)
			wm.EXPECT().Add(pemFile, mock.Anything).Return(nil)

			khr := mocks3.NewRegistryMock(t)
			khr.EXPECT().AddKeyHolder(mock.Anything)

			co := mocks4.NewObserverMock(t)
			co.EXPECT().Add(mock.Anything)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Watcher().Return(wm)
			appCtx.EXPECT().KeyHolderRegistry().Return(khr)
			appCtx.EXPECT().CertificateObserver().Return(co)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mctx.EXPECT().Context().Return(cache.WithContext(t.Context(), cch))

			finalizer, err := newJWTFinalizer(appCtx, uc, conf)
			require.NoError(t, err)

			configureMocks(t, finalizer, mctx, cch, tc.subject)

			// WHEN
			err = finalizer.Execute(mctx, tc.subject)

			// THEN
			tc.assert(t, err)
		})
	}
}
