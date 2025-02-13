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
	"context"
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

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, auth *basicAuthAuthenticator)
	}{
		{
			uc: "valid configuration without set fallback",
			id: "auth1",
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
				assert.False(t, auth.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		{
			uc: "valid configuration without fallback set to true",
			id: "auth1",
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
				assert.True(t, auth.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth1", auth.ID())
			},
		},
		{
			uc: "without user_id",
			config: []byte(`
password: bar`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		{
			uc: "without password",
			config: []byte(`
user_id: foo`),
			assert: func(t *testing.T, err error, auth *basicAuthAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)

				assert.Nil(t, auth)
			},
		},
		{
			uc: "with unexpected config attribute",
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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			auth, err := newBasicAuthAuthenticator(appCtx, tc.id, conf)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}

func TestCreateBasicAuthAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator)
	}{
		{
			uc: "no new configuration for the configured authenticator",
			id: "auth2",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "fallback on error set to true",
			id: "auth2",
			prototypeConfig: []byte(`
user_id: foo
password: bar`),
			config: []byte(`
allow_fallback_on_error: true
`),
			assert: func(t *testing.T, err error, prototype *basicAuthAuthenticator, configured *basicAuthAuthenticator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype.userID, configured.userID)
				assert.Equal(t, prototype.password, configured.password)
				assert.NotEqual(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.True(t, configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "password differs",
			id: "auth2",
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "no user_id provided",
			id: "auth2",
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "no password provided",
			id: "auth2",
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "user_id differs",
			id: "auth2",
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())
			},
		},
		{
			uc: "user_id and password differs",
			id: "auth2",
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
				assert.Equal(t, prototype.IsFallbackOnErrorAllowed(), configured.IsFallbackOnErrorAllowed())
				assert.Equal(t, "auth2", configured.ID())

				md := sha256.New()
				md.Write([]byte("baz"))
				value := hex.EncodeToString(md.Sum(nil))

				assert.Equal(t, value, configured.userID)
				assert.Equal(t, value, configured.password)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
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

			prototype, err := newBasicAuthAuthenticator(appCtx, tc.id, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			baa, ok := auth.(*basicAuthAuthenticator)
			require.True(t, ok)

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

	for _, tc := range []struct {
		uc               string
		id               string
		configureContext func(t *testing.T, ctx *mocks.RequestContextMock)
		assert           func(t *testing.T, err error, sub *subject.Subject)
	}{
		{
			uc: "no required header present",
			id: "auth3",
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
				assert.Equal(t, "auth3", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		{
			uc: "base64 decoding error",
			id: "auth3",
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
				assert.Equal(t, "auth3", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		{
			uc: "malformed encoding",
			id: "auth3",
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
				assert.Equal(t, "auth3", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		{
			uc: "invalid user id",
			id: "auth3",
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
				assert.Equal(t, "auth3", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		{
			uc: "invalid password",
			id: "auth3",
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
				assert.Equal(t, "auth3", identifier.ID())

				assert.Nil(t, sub)
			},
		},
		{
			uc: "valid credentials",
			id: "auth3",
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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			auth, err := newBasicAuthAuthenticator(appCtx, tc.id, conf)
			require.NoError(t, err)

			ctx := mocks.NewRequestContextMock(t)
			ctx.EXPECT().Context().Return(context.Background())
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
