package rules

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/testsupport"
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
			rul := &rule{methods: tc.methods}

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
			rul := &rule{urlMatcher: tc.matcher(t)}

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
		configureMocks func(
			t *testing.T,
			ctx *heimdallmocks.MockContext,
			authenticator *mocks.MockSubjectCreator,
			authorizer *mocks.MockSubjectHandler,
			mutator *mocks.MockSubjectHandler,
			errHandler *mocks.MockErrorHandler,
		)
		assert func(t *testing.T, err error)
	}{
		{
			uc: "authenticator fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, authenticator *mocks.MockSubjectCreator,
				authorizer *mocks.MockSubjectHandler, mutator *mocks.MockSubjectHandler,
				errHandler *mocks.MockErrorHandler,
			) {
				t.Helper()

				authenticator.On("Execute", ctx).Return(nil, testsupport.ErrTestPurpose)
				errHandler.On("Execute", ctx, testsupport.ErrTestPurpose).
					Return(true, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "authenticator fails, and error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, authenticator *mocks.MockSubjectCreator,
				authorizer *mocks.MockSubjectHandler, mutator *mocks.MockSubjectHandler,
				errHandler *mocks.MockErrorHandler,
			) {
				t.Helper()

				authenticator.On("Execute", ctx).Return(nil, testsupport.ErrTestPurpose)
				errHandler.On("Execute", ctx, testsupport.ErrTestPurpose).
					Return(true, testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, testsupport.ErrTestPurpose2)
			},
		},
		{
			uc: "authenticator succeeds, authorizer fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, authenticator *mocks.MockSubjectCreator,
				authorizer *mocks.MockSubjectHandler, mutator *mocks.MockSubjectHandler,
				errHandler *mocks.MockErrorHandler,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.On("Execute", ctx).Return(sub, nil)
				authorizer.On("Execute", ctx, sub).Return(testsupport.ErrTestPurpose)
				errHandler.On("Execute", ctx, testsupport.ErrTestPurpose).
					Return(true, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "authenticator succeeds, authorizer fails, but error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, authenticator *mocks.MockSubjectCreator,
				authorizer *mocks.MockSubjectHandler, mutator *mocks.MockSubjectHandler,
				errHandler *mocks.MockErrorHandler,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.On("Execute", ctx).Return(sub, nil)
				authorizer.On("Execute", ctx, sub).Return(testsupport.ErrTestPurpose)
				errHandler.On("Execute", ctx, testsupport.ErrTestPurpose).
					Return(true, testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, testsupport.ErrTestPurpose2)
			},
		},
		{
			uc: "authenticator succeeds, authorizer succeeds, mutator fails, but error handler succeeds",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, authenticator *mocks.MockSubjectCreator,
				authorizer *mocks.MockSubjectHandler, mutator *mocks.MockSubjectHandler,
				errHandler *mocks.MockErrorHandler,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.On("Execute", ctx).Return(sub, nil)
				authorizer.On("Execute", ctx, sub).Return(nil)
				mutator.On("Execute", ctx, sub).Return(testsupport.ErrTestPurpose)
				errHandler.On("Execute", ctx, testsupport.ErrTestPurpose).
					Return(true, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "authenticator succeeds, authorizer succeeds, mutator fails, but error handler fails",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, authenticator *mocks.MockSubjectCreator,
				authorizer *mocks.MockSubjectHandler, mutator *mocks.MockSubjectHandler,
				errHandler *mocks.MockErrorHandler,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.On("Execute", ctx).Return(sub, nil)
				authorizer.On("Execute", ctx, sub).Return(nil)
				mutator.On("Execute", ctx, sub).Return(testsupport.ErrTestPurpose)
				errHandler.On("Execute", ctx, testsupport.ErrTestPurpose).
					Return(true, testsupport.ErrTestPurpose2)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, testsupport.ErrTestPurpose2)
			},
		},
		{
			uc: "all handler succeed",
			configureMocks: func(t *testing.T, ctx *heimdallmocks.MockContext, authenticator *mocks.MockSubjectCreator,
				authorizer *mocks.MockSubjectHandler, mutator *mocks.MockSubjectHandler,
				errHandler *mocks.MockErrorHandler,
			) {
				t.Helper()

				sub := &subject.Subject{ID: "Foo"}

				authenticator.On("Execute", ctx).Return(sub, nil)
				authorizer.On("Execute", ctx, sub).Return(nil)
				mutator.On("Execute", ctx, sub).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := &heimdallmocks.MockContext{}
			ctx.On("AppContext").Return(context.Background())

			authenticator := &mocks.MockSubjectCreator{}
			authorizer := &mocks.MockSubjectHandler{}
			mutator := &mocks.MockSubjectHandler{}
			errHandler := &mocks.MockErrorHandler{}

			rul := &rule{
				sc: compositeSubjectCreator{authenticator},
				sh: compositeSubjectHandler{authorizer},
				m:  compositeSubjectHandler{mutator},
				eh: compositeErrorHandler{errHandler},
			}

			tc.configureMocks(t, ctx, authenticator, authorizer, mutator, errHandler)

			// WHEN
			err := rul.Execute(ctx)

			// THEN
			tc.assert(t, err)
		})
	}
}
