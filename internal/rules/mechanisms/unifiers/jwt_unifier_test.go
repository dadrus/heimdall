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

package unifiers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/mocks"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateJWTUnifier(t *testing.T) {
	t.Parallel()

	const expectedTTL = 5 * time.Second

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, unifier *jwtUnifier)
	}{
		{
			uc: "without config",
			id: "jun",
			assert: func(t *testing.T, err error, unifier *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, unifier)
				assert.Equal(t, defaultJWTTTL, unifier.ttl)
				assert.Nil(t, unifier.claims)
				assert.Equal(t, "jun", unifier.HandlerID())
			},
		},
		{
			uc:     "with empty config",
			id:     "jun",
			config: []byte(``),
			assert: func(t *testing.T, err error, unifier *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, unifier)
				assert.Equal(t, defaultJWTTTL, unifier.ttl)
				assert.Nil(t, unifier.claims)
				assert.Equal(t, "jun", unifier.HandlerID())
			},
		},
		{
			uc:     "with ttl only",
			id:     "jun",
			config: []byte(`ttl: 5s`),
			assert: func(t *testing.T, err error, unifier *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, unifier)
				assert.Equal(t, expectedTTL, unifier.ttl)
				assert.Nil(t, unifier.claims)
				assert.Equal(t, "jun", unifier.HandlerID())
			},
		},
		{
			uc:     "with too short ttl",
			config: []byte(`ttl: 5ms`),
			assert: func(t *testing.T, err error, _ *jwtUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "less than one second")
			},
		},
		{
			uc: "with claims only",
			id: "jun",
			config: []byte(`
claims: 
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, unifier *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, unifier)
				assert.Equal(t, defaultJWTTTL, unifier.ttl)
				require.NotNil(t, unifier.claims)
				val, err := unifier.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "jun", unifier.HandlerID())
				assert.False(t, unifier.ContinueOnError())
			},
		},
		{
			uc: "with claims and ttl",
			id: "jun",
			config: []byte(`
ttl: 5s
claims: 
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, unifier *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, unifier)
				assert.Equal(t, expectedTTL, unifier.ttl)
				require.NotNil(t, unifier.claims)
				val, err := unifier.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "jun", unifier.HandlerID())
				assert.False(t, unifier.ContinueOnError())
			},
		},
		{
			uc: "with unknown entries in configuration",
			config: []byte(`
ttl: 5s
foo: bar"
`),
			assert: func(t *testing.T, err error, _ *jwtUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			unifier, err := newJWTUnifier(tc.id, conf)

			// THEN
			tc.assert(t, err, unifier)
		})
	}
}

func TestCreateJWTUnifierFromPrototype(t *testing.T) {
	t.Parallel()

	const (
		expectedTTL = 5 * time.Second
	)

	for _, tc := range []struct {
		uc     string
		id     string
		config []byte
		assert func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier)
	}{
		{
			uc: "no new configuration provided",
			id: "jun1",
			assert: func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "jun1", configured.HandlerID())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc:     "empty configuration provided",
			id:     "jun2",
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "jun2", configured.HandlerID())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc:     "configuration with ttl only provided",
			id:     "jun3",
			config: []byte(`ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.claims, configured.claims)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.Equal(t, "jun3", configured.HandlerID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc:     "configuration with too short ttl",
			config: []byte(`ttl: 5ms`),
			assert: func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "less than one second")
			},
		},
		{
			uc: "configuration with claims only provided",
			id: "jun4",
			config: []byte(`
claims:
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.ttl, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				val, err := configured.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "jun4", configured.HandlerID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc: "configuration with both ttl and claims provided",
			id: "jun5",
			config: []byte(`
ttl: 5s
claims:
  '{ "sub": {{ quote .Subject.ID }} }'
`),
			assert: func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, expectedTTL, configured.ttl)
				assert.NotEqual(t, prototype.claims, configured.claims)
				require.NotNil(t, configured.claims)
				val, err := configured.claims.Render(map[string]any{
					"Subject": &subject.Subject{ID: "bar"},
				})
				require.NoError(t, err)
				assert.Equal(t, `{ "sub": "bar" }`, val)
				assert.Equal(t, "jun5", configured.HandlerID())
				assert.False(t, prototype.ContinueOnError())
				assert.False(t, configured.ContinueOnError())
			},
		},
		{
			uc: "with unknown entries in configuration",
			config: []byte(`
ttl: 5s
foo: bar
`),
			assert: func(t *testing.T, err error, prototype *jwtUnifier, configured *jwtUnifier) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newJWTUnifier(tc.id, nil)
			require.NoError(t, err)

			// WHEN
			unifier, err := prototype.WithConfig(conf)

			// THEN
			var (
				jwtUn *jwtUnifier
				ok    bool
			)

			if err == nil {
				jwtUn, ok = unifier.(*jwtUnifier)
				require.True(t, ok)
			}

			tc.assert(t, err, prototype, jwtUn)
		})
	}
}

func TestJWTUnifierExecute(t *testing.T) {
	t.Parallel()

	const configuredTTL = 1 * time.Minute

	for _, tc := range []struct {
		uc             string
		id             string
		config         []byte
		subject        *subject.Subject
		configureMocks func(t *testing.T,
			ctx *heimdallmocks.ContextMock,
			signer *heimdallmocks.JWTSignerMock,
			cch *mocks.CacheMock,
			sub *subject.Subject)
		assert func(t *testing.T, err error)
	}{
		{
			uc: "with 'nil' subject",
			id: "jun1",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "jun1", identifier.HandlerID())
			},
		},
		{
			uc:      "with used prefilled cache",
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, signer *heimdallmocks.JWTSignerMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				signer.EXPECT().Hash().Return([]byte("foobar"))

				ctx.EXPECT().Signer().Return(signer)
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer TestToken")

				unifier := jwtUnifier{ttl: defaultJWTTTL}

				cacheKey := unifier.calculateCacheKey(sub, signer)
				cch.EXPECT().Get(cacheKey).Return("TestToken")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:      "with bad prefilled cache and without custom claims",
			config:  []byte(`ttl: 1m`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, signer *heimdallmocks.JWTSignerMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				signer.EXPECT().Hash().Return([]byte("foobar"))
				signer.EXPECT().Sign(sub.ID, configuredTTL, map[string]any{}).
					Return("barfoo", nil)

				ctx.EXPECT().Signer().Return(signer)
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer barfoo")

				unifier := jwtUnifier{ttl: configuredTTL}
				cacheKey := unifier.calculateCacheKey(sub, signer)

				cch.EXPECT().Get(cacheKey).Return(time.Second)
				cch.EXPECT().Delete(cacheKey)
				cch.EXPECT().Set(cacheKey, "barfoo", configuredTTL-defaultCacheLeeway)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:      "with no cache hit and without custom claims",
			config:  []byte(`ttl: 1m`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, signer *heimdallmocks.JWTSignerMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				signer.EXPECT().Hash().Return([]byte("foobar"))
				signer.EXPECT().Sign(sub.ID, configuredTTL, map[string]any{}).
					Return("barfoo", nil)

				ctx.EXPECT().Signer().Return(signer)
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer barfoo")

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, "barfoo", configuredTTL-defaultCacheLeeway)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc: "with no cache hit and with custom claims",
			config: []byte(`
claims: '{
  {{ $val := .Subject.Attributes.baz }}
  "sub_id": {{ quote .Subject.ID }}, 
  {{ quote $val }}: "baz"
}'`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, signer *heimdallmocks.JWTSignerMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				signer.EXPECT().Hash().Return([]byte("foobar"))
				signer.EXPECT().Sign(sub.ID, defaultJWTTTL, map[string]any{
					"sub_id": "foo",
					"bar":    "baz",
				}).Return("barfoo", nil)

				ctx.EXPECT().Signer().Return(signer)
				ctx.EXPECT().AddHeaderForUpstream("Authorization", "Bearer barfoo")
				ctx.EXPECT().Request().Return(&heimdall.Request{})

				cch.EXPECT().Get(mock.Anything).Return(nil)
				cch.EXPECT().Set(mock.Anything, "barfoo", defaultJWTTTL-defaultCacheLeeway)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:      "with custom claims template, which does not result in a JSON object",
			id:      "jun2",
			config:  []byte(`claims: "foo: bar"`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, signer *heimdallmocks.JWTSignerMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				signer.EXPECT().Hash().Return([]byte("foobar"))

				ctx.EXPECT().Signer().Return(signer)
				ctx.EXPECT().Request().Return(&heimdall.Request{})

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to unmarshal claims")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "jun2", identifier.HandlerID())
			},
		},
		{
			uc:      "with custom claims template, which fails during rendering",
			id:      "jun3",
			config:  []byte(`claims: "{{ len .foobar }}"`),
			subject: &subject.Subject{ID: "foo", Attributes: map[string]any{"baz": "bar"}},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, signer *heimdallmocks.JWTSignerMock,
				cch *mocks.CacheMock, sub *subject.Subject,
			) {
				t.Helper()

				signer.EXPECT().Hash().Return([]byte("foobar"))

				ctx.EXPECT().Signer().Return(signer)
				ctx.EXPECT().Request().Return(&heimdall.Request{})

				cch.EXPECT().Get(mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "jun3", identifier.HandlerID())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *heimdallmocks.ContextMock, _ *heimdallmocks.JWTSignerMock,
					_ *mocks.CacheMock, _ *subject.Subject,
				) {
					t.Helper()
				})

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			cch := mocks.NewCacheMock(t)
			mctx := heimdallmocks.NewContextMock(t)
			signer := heimdallmocks.NewJWTSignerMock(t)

			mctx.EXPECT().AppContext().Return(cache.WithContext(context.Background(), cch))
			configureMocks(t, mctx, signer, cch, tc.subject)

			unifier, err := newJWTUnifier(tc.id, conf)
			require.NoError(t, err)

			// WHEN
			err = unifier.Execute(mctx, tc.subject)

			// THEN
			tc.assert(t, err)
		})
	}
}
