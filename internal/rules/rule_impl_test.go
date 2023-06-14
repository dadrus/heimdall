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

	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
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
		toBeMatched *url.URL
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
			toBeMatched: &url.URL{Scheme: "http", Host: "foo.bar", Path: "baz"},
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
			toBeMatched: &url.URL{Scheme: "https", Host: "foo.bar", Path: "baz"},
			assert: func(t *testing.T, matched bool) {
				t.Helper()

				assert.False(t, matched)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			rul := &ruleImpl{urlMatcher: tc.matcher(t)}

			// WHEN
			matched := rul.MatchesURL(tc.toBeMatched)

			// THEN
			tc.assert(t, matched)
		})
	}
}

func TestRuleExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		upstreamURL    *url.URL
		stripPrefix    string
		configureMocks func(
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
			uc:          "authenticator fails, but error handler succeeds",
			upstreamURL: &url.URL{Scheme: "http", Host: "test.local", Path: "foo"},
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
			uc:          "authenticator fails, and error handler fails",
			upstreamURL: &url.URL{Scheme: "http", Host: "test.local", Path: "foo"},
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
			uc:          "authenticator succeeds, authorizer fails, but error handler succeeds",
			upstreamURL: &url.URL{Scheme: "http", Host: "test.local", Path: "foo"},
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
			uc:          "authenticator succeeds, authorizer fails and error handler fails",
			upstreamURL: &url.URL{Scheme: "http", Host: "test.local", Path: "foo"},
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
			uc:          "authenticator succeeds, authorizer succeeds, unifier fails, but error handler succeeds",
			upstreamURL: &url.URL{Scheme: "http", Host: "test.local", Path: "foo"},
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
			uc:          "authenticator succeeds, authorizer succeeds, unifier fails and error handler fails",
			upstreamURL: &url.URL{Scheme: "http", Host: "test.local", Path: "foo"},
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
			uc:          "all handler succeed",
			upstreamURL: &url.URL{Scheme: "https", Host: "test.local"},
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

				assert.Equal(t, &url.URL{Scheme: "https", Host: "test.local", Path: "/foo"}, upstreamURL)
			},
		},
		{
			uc:          "stripping path prefix",
			upstreamURL: &url.URL{Scheme: "http", Host: "test.local"},
			stripPrefix: "api/v1",
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

				upstreamURL, err := mutator.Mutate(&url.URL{Scheme: "http", Host: "foo.local", Path: "api/v1/foo"})
				require.NoError(t, err)

				assert.Equal(t, &url.URL{Scheme: "http", Host: "test.local", Path: "/foo"}, upstreamURL)
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
				upstreamURL: tc.upstreamURL,
				stripPrefix: tc.stripPrefix,
				sc:          compositeSubjectCreator{authenticator},
				sh:          compositeSubjectHandler{authorizer},
				un:          compositeSubjectHandler{unifier},
				eh:          compositeErrorHandler{errHandler},
			}

			tc.configureMocks(t, ctx, authenticator, authorizer, unifier, errHandler)

			// WHEN
			urlMutator, err := rul.Execute(ctx)

			// THEN
			tc.assert(t, err, urlMutator)
		})
	}
}
