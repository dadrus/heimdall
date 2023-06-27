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
		uc          string
		matcher     func(t *testing.T) patternmatcher.PatternMatcher
		toBeMatched string
		assert      func(t *testing.T, matched bool)
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
			rul := &ruleImpl{urlMatcher: tc.matcher(t)}

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
		uc                 string
		upstreamURLFactory UpstreamURLFactory
		configureMocks     func(
			t *testing.T,
			ctx *heimdallmocks.ContextMock,
			authenticator *mocks.SubjectCreatorMock,
			authorizer *mocks.SubjectHandlerMock,
			unifier *mocks.SubjectHandlerMock,
			errHandler *mocks.ErrorHandlerMock,
		)
		assert func(t *testing.T, err error, mutator rule.URIMutator)
	}{
		{
			uc: "authenticator fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx).Return(nil, testsupport.ErrTestPurpose)
				authenticator.EXPECT().IsFallbackOnErrorAllowed().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, nil)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, mutator)
			},
		},
		{
			uc: "authenticator fails, and error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx).Return(nil, testsupport.ErrTestPurpose)
				authenticator.EXPECT().IsFallbackOnErrorAllowed().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, testsupport.ErrTestPurpose2)
				assert.Nil(t, mutator)
			},
		},
		{
			uc: "authenticator succeeds, authorizer fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				authorizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, nil)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, mutator)
			},
		},
		{
			uc: "authenticator succeeds, authorizer fails and error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				authorizer.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, testsupport.ErrTestPurpose2)
				assert.Nil(t, mutator)
			},
		},
		{
			uc: "authenticator succeeds, authorizer succeeds, unifier fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				unifier.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				unifier.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, nil)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, mutator)
			},
		},
		{
			uc: "authenticator succeeds, authorizer succeeds, unifier fails and error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				unifier.EXPECT().Execute(ctx, sub).Return(testsupport.ErrTestPurpose)
				unifier.EXPECT().ContinueOnError().Return(false)
				errHandler.EXPECT().Execute(ctx, testsupport.ErrTestPurpose).Return(true, testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, testsupport.ErrTestPurpose2)
				assert.Nil(t, mutator)
			},
		},
		{
			uc: "all handler succeed",
			upstreamURLFactory: &config.UpstreamURLFactory{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				unifier.EXPECT().Execute(ctx, sub).Return(nil)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.NoError(t, err)

				upstreamURL, err := mutator.Mutate(&url.URL{Scheme: "http", Host: "foo.local", Path: "/foo"})
				require.NoError(t, err)

				assert.Equal(t, &url.URL{Scheme: "http", Host: "foo.bar", Path: "/foo"}, upstreamURL)
			},
		},
		{
			uc: "stripping path prefix",
			upstreamURLFactory: &config.UpstreamURLFactory{
				Host:        "foo.bar",
				URLRewriter: &config.URLRewriter{PathPrefixToCut: "/api/v1"},
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *mocks.SubjectCreatorMock,
				authorizer *mocks.SubjectHandlerMock, unifier *mocks.SubjectHandlerMock,
				errHandler *mocks.ErrorHandlerMock,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.EXPECT().Execute(ctx).Return(sub, nil)
				authorizer.EXPECT().Execute(ctx, sub).Return(nil)
				unifier.EXPECT().Execute(ctx, sub).Return(nil)
			},
			assert: func(t *testing.T, err error, mutator rule.URIMutator) {
				t.Helper()

				require.NoError(t, err)

				upstreamURL, err := mutator.Mutate(&url.URL{Scheme: "http", Host: "foo.local", Path: "/api/v1/foo"})
				require.NoError(t, err)

				assert.Equal(t, &url.URL{Scheme: "http", Host: "foo.bar", Path: "/foo"}, upstreamURL)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := heimdallmocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background())

			authenticator := mocks.NewSubjectCreatorMock(t)
			authorizer := mocks.NewSubjectHandlerMock(t)
			unifier := mocks.NewSubjectHandlerMock(t)
			errHandler := mocks.NewErrorHandlerMock(t)

			rul := &ruleImpl{
				upstreamURLFactory: tc.upstreamURLFactory,
				sc:                 compositeSubjectCreator{authenticator},
				sh:                 compositeSubjectHandler{authorizer},
				un:                 compositeSubjectHandler{unifier},
				eh:                 compositeErrorHandler{errHandler},
			}

			tc.configureMocks(t, ctx, authenticator, authorizer, unifier, errHandler)

			// WHEN
			urlMutator, err := rul.Execute(ctx)

			// THEN
			tc.assert(t, err, urlMutator)
		})
	}
}

func TestRuleMutate(t *testing.T) {
	t.Parallel()

	origURL := &url.URL{Scheme: "http", Host: "foo.bar", Path: "/foo"}

	for _, tc := range []struct {
		uc         string
		urlFactory UpstreamURLFactory
		err        error
	}{
		{
			uc:  "no upstream url factory defined",
			err: heimdall.ErrConfiguration,
		},
		{
			uc: "upstream url factory defined",
			urlFactory: func() UpstreamURLFactory {
				factoryMock := mocks.NewUpstreamURLFactoryMock(t)
				factoryMock.EXPECT().CreateURL(origURL).Return(nil)

				return factoryMock
			}(),
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			rul := &ruleImpl{upstreamURLFactory: tc.urlFactory}

			// WHEN
			_, err := rul.Mutate(origURL)

			// THEN
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}
