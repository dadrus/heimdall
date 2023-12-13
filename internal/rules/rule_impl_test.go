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
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestRuleMatchMethod(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		methods     []string
		toBeMatched string
		assert      func(t *testing.T, matched bool)
	}{
		{
			uc:          "matches",
			methods:     []string{"FOO", "BAR"},
			toBeMatched: "BAR",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.True(t, matched)
			},
		},
		{
			uc:          "doesn't match",
			methods:     []string{"FOO", "BAR"},
			toBeMatched: "BAZ",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.False(t, matched)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			rul := &ruleImpl{methods: tc.methods}

			// WHEN
			matched := rul.MatchesMethod(tc.toBeMatched)

			// THEN
			tc.assert(t, matched)
		})
	}
}

func TestRuleMatchURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		slashHandling config.EncodedSlashesHandling
		matcher       func(t *testing.T) patternmatcher.PatternMatcher
		toBeMatched   string
		assert        func(t *testing.T, matched bool)
	}{
		{
			uc: "matches",
			matcher: func(t *testing.T) patternmatcher.PatternMatcher {
				t.Helper()

				matcher, err := patternmatcher.NewPatternMatcher("glob", "http://foo.bar/baz")
				require.NoError(t, err)

				return matcher
			},
			toBeMatched: "http://foo.bar/baz",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.True(t, matched)
			},
		},
		{
			uc: "matches with urlencoded path fragments",
			matcher: func(t *testing.T) patternmatcher.PatternMatcher {
				t.Helper()

				matcher, err := patternmatcher.NewPatternMatcher("glob", "http://foo.bar/[id]/baz")
				require.NoError(t, err)

				return matcher
			},
			toBeMatched: "http://foo.bar/%5Bid%5D/baz",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.True(t, matched)
			},
		},
		{
			uc: "doesn't match with urlencoded slash in path",
			matcher: func(t *testing.T) patternmatcher.PatternMatcher {
				t.Helper()

				matcher, err := patternmatcher.NewPatternMatcher("glob", "http://foo.bar/foo%2Fbaz")
				require.NoError(t, err)

				return matcher
			},
			toBeMatched: "http://foo.bar/foo%2Fbaz",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.False(t, matched)
			},
		},
		{
			uc:            "matches with urlencoded slash in path if allowed with decoding",
			slashHandling: config.EncodedSlashesOn,
			matcher: func(t *testing.T) patternmatcher.PatternMatcher {
				t.Helper()

				matcher, err := patternmatcher.NewPatternMatcher("glob", "http://foo.bar/foo/baz/[id]")
				require.NoError(t, err)

				return matcher
			},
			toBeMatched: "http://foo.bar/foo%2Fbaz/%5Bid%5D",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.True(t, matched)
			},
		},
		{
			uc:            "matches with urlencoded slash in path if allowed without decoding",
			slashHandling: config.EncodedSlashesNoDecode,
			matcher: func(t *testing.T) patternmatcher.PatternMatcher {
				t.Helper()

				matcher, err := patternmatcher.NewPatternMatcher("glob", "http://foo.bar/foo%2Fbaz/[id]")
				require.NoError(t, err)

				return matcher
			},
			toBeMatched: "http://foo.bar/foo%2Fbaz/%5Bid%5D",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.True(t, matched)
			},
		},
		{
			uc: "doesn't match",
			matcher: func(t *testing.T) patternmatcher.PatternMatcher {
				t.Helper()

				matcher, err := patternmatcher.NewPatternMatcher("glob", "http://foo.bar/baz")
				require.NoError(t, err)

				return matcher
			},
			toBeMatched: "https://foo.bar/baz",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.False(t, matched)
			},
		},
		{
			uc: "query params are ignored while matching",
			matcher: func(t *testing.T) patternmatcher.PatternMatcher {
				t.Helper()

				matcher, err := patternmatcher.NewPatternMatcher("glob", "http://foo.bar/baz")
				require.NoError(t, err)

				return matcher
			},
			toBeMatched: "https://foo.bar/baz?foo=bar",
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.False(t, matched)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			rul := &ruleImpl{
				urlMatcher:             tc.matcher(t),
				encodedSlashesHandling: x.IfThenElse(len(tc.slashHandling) != 0, tc.slashHandling, config.EncodedSlashesOff),
			}

			tbmu, err := url.Parse(tc.toBeMatched)
			require.NoError(t, err)

			// WHEN
			matched := rul.MatchesURL(tbmu)

			// THEN
			tc.assert(t, matched)
		})
	}
}

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
		assert func(t *testing.T, err error, backend rule.Backend)
	}{
		{
			uc: "authenticator fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				_ *mocks.SubjectHandlerMock, _ *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx).Return(nil, testsupport.ErrTestPurpose)
				authenticator.EXPECT().IsFallbackOnErrorAllowed().Return(false)
				errHandler.EXPECT().CanExecute(ctx, testsupport.ErrTestPurpose).Return(true)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
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

				authenticator.EXPECT().Execute(ctx).Return(nil, testsupport.ErrTestPurpose)
				authenticator.EXPECT().IsFallbackOnErrorAllowed().Return(false)
				errHandler.EXPECT().CanExecute(ctx, testsupport.ErrTestPurpose).Return(true)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
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

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				authorizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().CanExecute(ctx, testsupport.ErrTestPurpose).Return(true)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
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

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				authorizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().CanExecute(ctx, testsupport.ErrTestPurpose).Return(true)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
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

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				finalizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().CanExecute(ctx, testsupport.ErrTestPurpose).Return(true)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
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

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				finalizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				finalizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().CanExecute(ctx, testsupport.ErrTestPurpose).Return(true)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, testsupport.ErrTestPurpose2)
				assert.Nil(t, backend)
			},
		},
		{
			uc: "all handler succeed with disallowed urlencoded slashes",
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
				ctx.EXPECT().Request().Return(&heimdall.Request{URL: targetURL})
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())
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
				ctx.EXPECT().Request().Return(&heimdall.Request{URL: targetURL})
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())
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
				ctx.EXPECT().Request().Return(&heimdall.Request{URL: targetURL})
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())
			},
		},
		{
			uc:            "all handler succeed with urlencoded slashes on with urlencoded slash but without decoding it",
			slashHandling: config.EncodedSlashesNoDecode,
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
				ctx.EXPECT().Request().Return(&heimdall.Request{URL: targetURL})
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api%2Fv1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())
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
				ctx.EXPECT().Request().Return(&heimdall.Request{URL: targetURL})
			},
			assert: func(t *testing.T, err error, backend rule.Backend) {
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
				backend:                tc.backend,
				encodedSlashesHandling: x.IfThenElse(len(tc.slashHandling) != 0, tc.slashHandling, config.EncodedSlashesOff),
				sc:                     compositeSubjectCreator{authenticator},
				sh:                     compositeSubjectHandler{authorizer},
				fi:                     compositeSubjectHandler{finalizer},
				eh:                     compositeErrorHandler{errHandler},
			}

			tc.configureMocks(t, ctx, authenticator, authorizer, finalizer, errHandler)

			// WHEN
			upstream, err := rul.Execute(ctx)

			// THEN
			tc.assert(t, err, upstream)
		})
	}
}
