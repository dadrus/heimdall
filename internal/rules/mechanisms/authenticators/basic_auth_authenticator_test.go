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

package authenticators

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateBasicAuthAuthenticator(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, auth *basicAuthAuthenticator)
	}{
		"valid configuration without set fallback": {
			config: []byte(`
user_id: foo
password: bar`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				md := sha256.New()
				md.Write([]byte("foo"))
				userID := hex.EncodeToString(md.Sum(nil))

				md.Reset()
				md.Write([]byte("bar"))
				password := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, userID, auth.userID)
				assert.Equal(t, password, auth.password)
				assert.Equal(t, "valid configuration without set fallback", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Empty(t, auth.emptyAttributes)
				assert.NotNil(t, auth.emptyAttributes)
			},
		},
		"valid configuration without fallback set to true": {
			config: []byte(`
user_id: foo
password: bar
allow_fallback_on_error: true
`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				md := sha256.New()
				md.Write([]byte("foo"))
				userID := hex.EncodeToString(md.Sum(nil))

				md.Reset()
				md.Write([]byte("bar"))
				password := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, userID, auth.userID)
				assert.Equal(t, password, auth.password)
				assert.Equal(t, "valid configuration without fallback set to true", auth.ID())
				assert.Equal(t, auth.ID(), auth.Name())
				assert.Empty(t, auth.emptyAttributes)
				assert.NotNil(t, auth.emptyAttributes)
			},
		},
		"without user_id": {
			config: []byte(`
password: bar`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		"without password": {
			config: []byte(`
user_id: foo`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		"with unexpected config attribute": {
			config: []byte(`
user_id: foo
password: bar
foo: bar`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			auth, err := newBasicAuthAuthenticator(appCtx, uc, conf)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}

func TestCreateBasicAuthAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		stepID          string
		assert          func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator)
	}{
		"no new configuration for the configured authenticator": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "no new configuration for the configured authenticator", configured.ID())
			},
		},
		"password differs": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: foo
password: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.Equal(t, prototype.userID, configured.userID)
				assert.NotEqual(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "password differs", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
			},
		},
		"no user_id provided": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
password: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.Equal(t, prototype.userID, configured.userID)
				assert.NotEqual(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "no user_id provided", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
			},
		},
		"no password provided": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "no password provided", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
			},
		},
		"user_id differs": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: baz
password: bar`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "user_id differs", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
			},
		},
		"user_id and password differs": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
user_id: baz
password: baz`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)

				assert.NotEqual(t, prototype.userID, configured.userID)
				assert.NotEqual(t, prototype.password, configured.password)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, "user_id and password differs", configured.ID())
				assert.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)

				md := sha256.New()
				md.Write([]byte("baz"))
				value := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, value, configured.userID)
				assert.Equal(t, value, configured.password)
			},
		},
		"step id configured": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			stepID: "foo",
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				require.Equal(t, prototype.Name(), configured.Name())
				require.NotEqual(t, prototype.ID(), configured.ID())
				require.Equal(t, "foo", configured.ID())
				require.Equal(t, prototype.userID, configured.userID)
				require.Equal(t, prototype.password, configured.password)
				require.Equal(t, prototype.ads, configured.ads)
				require.Equal(t, prototype.app, configured.app)
				require.Equal(t, prototype.emptyAttributes, configured.emptyAttributes)
			},
		},
		"decoding error": {
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *basicAuthAuthenticator, _ *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding config")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prototype, err := newBasicAuthAuthenticator(appCtx, uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(tc.stepID, conf)

			// THEN
			baa, ok := auth.(*basicAuthAuthenticator)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, baa)
		})
	}
}

func TestBasicAuthAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	type HandlerIdentifier interface {
		ID() string
	}

	conf, err := testsupport.DecodeTestConfig([]byte(`
user_id: foo
password: bar`))
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		configureContext func(t *testing.T, ctx *mocks.RequestContextMock)
		assert           func(t *testing.T, err error, sub *subject.Subject)
	}{
		"no required header present": {
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").Return("")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "expected header not present")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "no required header present", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		"base64 decoding error": {
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").Return("Basic bar")

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "failed to decode")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "base64 decoding error", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		"malformed encoding": {
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo|bar")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "malformed user-id - password")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "malformed encoding", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		"invalid user id": {
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("baz:bar")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				require.Contains(t, err.Error(), "invalid user credentials")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "invalid user id", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		"invalid password": {
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo:baz")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrAuthentication)
				require.NotErrorIs(t, err, heimdall.ErrArgument)
				assert.Contains(t, err.Error(), "invalid user credentials")

				var identifier HandlerIdentifier
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "invalid password", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		"valid credentials": {
			configureContext: func(t *testing.T, ctx *mocks.RequestContextMock) {
				t.Helper()

				fnt := mocks.NewRequestFunctionsMock(t)
				fnt.EXPECT().Header("Authorization").
					Return("Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar")))

				ctx.EXPECT().Request().Return(&heimdall.Request{RequestFunctions: fnt})
			},
			assert: func(t *testing.T, err error, sub *subject.Subject) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sub)

				require.Equal(t, "foo", sub.ID)
				assert.NotNil(t, sub.Attributes)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			auth, err := newBasicAuthAuthenticator(appCtx, uc, conf)
			require.NoError(t, err)

			ctx := mocks.NewRequestContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())
			tc.configureContext(t, ctx)

			// WHEN
			sub, err := auth.Execute(ctx)

			// THEN
			tc.assert(t, err, sub)
		})
	}
}

func TestBasicAuthAuthenticatorIsInsecure(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := basicAuthAuthenticator{}

	// WHEN & THEN
	require.False(t, auth.IsInsecure())
}
