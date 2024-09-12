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

package rules

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestRuleExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		backend        *config.Backend
		slashHandling  config.EncodedSlashesHandling
		configureMocks func(
			t *testing.T,
			ctx *heimdallmocks.ContextMock,
			authenticator *mocks.SubjectCreatorMock,
			authorizer *mocks.SubjectHandlerMock,
			finalizer *mocks.SubjectHandlerMock,
			errHandler *mocks.ErrorHandlerMock,
		)
		assert func(t *testing.T, err error, backend rule.Backend, captures map[string]string)
	}{
		{
			uc: "authenticator fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				_ *mocks.SubjectHandlerMock, _ *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{}})

				authenticator.EXPECT().Execute(ctx).Return(nil, testsupport.ErrTestPurpose)
				authenticator.EXPECT().IsFallbackOnErrorAllowed().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, backend)
			},
		},
		{
			uc: "authenticator fails, and error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				_ *mocks.SubjectHandlerMock, _ *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{}})

				authenticator.EXPECT().Execute(ctx).Return(nil, testsupport.ErrTestPurpose)
				authenticator.EXPECT().IsFallbackOnErrorAllowed().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, testsupport.ErrTestPurpose2)
				assert.Nil(t, backend)
			},
		},
		{
			uc: "authenticator succeeds, authorizer fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, _ *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{}})

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				authorizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, backend)
			},
		},
		{
			uc: "authenticator succeeds, authorizer fails and error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, _ *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{}})

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				authorizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, testsupport.ErrTestPurpose2)
				assert.Nil(t, backend)
			},
		},
		{
			uc: "authenticator succeeds, authorizer succeeds, finalizer fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, finalizer *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{}})

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				finalizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, backend)
			},
		},
		{
			uc: "authenticator succeeds, authorizer succeeds, finalizer fails and error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, finalizer *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{}})

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				finalizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, testsupport.ErrTestPurpose2)
				assert.Nil(t, backend)
			},
		},
		{
			uc:            "all handler succeed with disallowed urlencoded slashes",
			slashHandling: config.EncodedSlashesOff,
			backend: &config.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, _ *mocks.SubjectCreatorMock,
				_ *mocks.SubjectHandlerMock, _ *mocks.SubjectHandlerMock, _ *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				targetURL, _ := url.Parse("http://foo.local/api%2Fv1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&heimdall.Request{
					URL: &heimdall.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api%2Fv1", "second": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, _ rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrArgument)
				require.ErrorContains(t, err, "path contains encoded slash")
			},
		},
		{
			uc:            "all handler succeed with urlencoded slashes on without urlencoded slash",
			slashHandling: config.EncodedSlashesOn,
			backend: &config.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, finalizer *mocks.SubjectHandlerMock,
				_ *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api/v1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&heimdall.Request{
					URL: &heimdall.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api", "second": "v1", "third": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, captures map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())

				assert.Equal(t, "api", captures["first"])
				assert.Equal(t, "v1", captures["second"])
				assert.Equal(t, "foo[id]", captures["third"])
			},
		},
		{
			uc:            "all handler succeed with urlencoded slashes on with urlencoded slash",
			slashHandling: config.EncodedSlashesOn,
			backend: &config.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, finalizer *mocks.SubjectHandlerMock,
				_ *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api%2Fv1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&heimdall.Request{
					URL: &heimdall.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api%2Fv1", "second": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, captures map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())

				assert.Equal(t, "api/v1", captures["first"])
				assert.Equal(t, "foo[id]", captures["second"])
			},
		},
		{
			uc:            "all handler succeed with urlencoded slashes on with urlencoded slash but without decoding it",
			slashHandling: config.EncodedSlashesOnNoDecode,
			backend: &config.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, finalizer *mocks.SubjectHandlerMock,
				_ *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api%2Fv1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&heimdall.Request{
					URL: &heimdall.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api%2Fv1", "second": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, captures map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api%2Fv1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())

				assert.Equal(t, "api%2Fv1", captures["first"])
				assert.Equal(t, "foo[id]", captures["second"])
			},
		},
		{
			uc: "stripping path prefix",
			backend: &config.Backend{
				Host:        "foo.bar",
				URLRewriter: &config.URLRewriter{PathPrefixToCut: "/api/v1"},
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, finalizer *mocks.SubjectHandlerMock,
				_ *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api/v1/foo")
				ctx.EXPECT().Request().Return(&heimdall.Request{URL: &heimdall.URL{URL: *targetURL}})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/foo")
				assert.Equal(t, expectedURL, backend.URL())
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := heimdallmocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background())

			authenticator := mocks.NewSubjectCreatorMock(t)
			authorizer := mocks.NewSubjectHandlerMock(t)
			finalizer := mocks.NewSubjectHandlerMock(t)
			errHandler := mocks.NewErrorHandlerMock(t)

			rul := &ruleImpl{
				backend:         tc.backend,
				slashesHandling: x.IfThenElse(len(tc.slashHandling) != 0, tc.slashHandling, config.EncodedSlashesOff),
				sc:              compositeSubjectCreator{authenticator},
				sh:              compositeSubjectHandler{authorizer},
				fi:              compositeSubjectHandler{finalizer},
				eh:              compositeErrorHandler{errHandler},
			}

			tc.configureMocks(t, ctx, authenticator, authorizer, finalizer, errHandler)

			// WHEN
			upstream, err := rul.Execute(ctx)

			// THEN
			tc.assert(t, err, upstream, ctx.Request().URL.Captures)
		})
	}
}
