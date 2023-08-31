package rules

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	mocks2 "github.com/dadrus/heimdall/internal/heimdall/mocks"
	mocks4 "github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

func TestRuleExecutorExecute(t *testing.T) {
	t.Parallel()

	matchingURL, err := url.Parse("https://foo.bar/test")
	require.NoError(t, err)

	for _, tc := range []struct {
		uc             string
		expErr         error
		requireURL     bool
		createRequest  func(t *testing.T) *http.Request
		configureMocks func(t *testing.T, ctx *mocks2.ContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock)
		assertResponse func(t *testing.T, err error, response *http.Response)
	}{
		{
			uc:     "no rules configured",
			expErr: heimdall.ErrNoRuleFound,
			configureMocks: func(t *testing.T, ctx *mocks2.ContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{Method: http.MethodPost, URL: matchingURL})
				repo.EXPECT().FindRule(matchingURL).Return(nil, heimdall.ErrNoRuleFound)
			},
		},
		{
			uc:     "rule doesn't match method",
			expErr: heimdall.ErrMethodNotAllowed,
			configureMocks: func(t *testing.T, ctx *mocks2.ContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{Method: http.MethodPost, URL: matchingURL})
				rule.EXPECT().MatchesMethod(http.MethodPost).Return(false)
				rule.EXPECT().ID().Return("test_id")
				rule.EXPECT().SrcID().Return("test_src")
				repo.EXPECT().FindRule(matchingURL).Return(rule, nil)
			},
		},
		{
			uc:     "rule execution fails with authentication error",
			expErr: heimdall.ErrAuthentication,
			configureMocks: func(t *testing.T, ctx *mocks2.ContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{Method: http.MethodGet, URL: matchingURL})
				rule.EXPECT().MatchesMethod(http.MethodGet).Return(true)
				rule.EXPECT().Execute(ctx).Return(nil, heimdall.ErrAuthentication)
				repo.EXPECT().FindRule(matchingURL).Return(rule, nil)
			},
		},
		{
			uc:         "rule execution succeeds, but url retrieval fails",
			requireURL: true,
			expErr:     heimdall.ErrInternal,
			configureMocks: func(t *testing.T, ctx *mocks2.ContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				mut := mocks4.NewURIMutatorMock(t)
				mut.EXPECT().Mutate(matchingURL).Return(nil, heimdall.ErrInternal)

				ctx.EXPECT().Request().Return(&heimdall.Request{Method: http.MethodGet, URL: matchingURL})
				rule.EXPECT().MatchesMethod(http.MethodGet).Return(true)
				rule.EXPECT().Execute(ctx).Return(mut, nil)
				repo.EXPECT().FindRule(matchingURL).Return(rule, nil)
			},
		},
		{
			uc: "rule execution succeeds, without url retrieval",
			configureMocks: func(t *testing.T, ctx *mocks2.ContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(&heimdall.Request{Method: http.MethodGet, URL: matchingURL})
				rule.EXPECT().MatchesMethod(http.MethodGet).Return(true)
				rule.EXPECT().Execute(ctx).Return(nil, nil)
				repo.EXPECT().FindRule(matchingURL).Return(rule, nil)
			},
		},
		{
			uc:         "rule execution with url retrieval succeeds",
			requireURL: true,
			configureMocks: func(t *testing.T, ctx *mocks2.ContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				mut := mocks4.NewURIMutatorMock(t)
				mut.EXPECT().Mutate(matchingURL).Return(matchingURL, nil)

				ctx.EXPECT().Request().Return(&heimdall.Request{Method: http.MethodGet, URL: matchingURL})
				rule.EXPECT().MatchesMethod(http.MethodGet).Return(true)
				rule.EXPECT().Execute(ctx).Return(mut, nil)
				repo.EXPECT().FindRule(matchingURL).Return(rule, nil)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			repo := mocks4.NewRepositoryMock(t)
			rule := mocks4.NewRuleMock(t)
			ctx := mocks2.NewContextMock(t)

			tc.configureMocks(t, ctx, repo, rule)

			exec := newRuleExecutor(repo)

			// WHEN
			targetURL, err := exec.Execute(ctx, tc.requireURL)

			// THEN
			if tc.expErr != nil {
				require.ErrorIs(t, err, tc.expErr)
			} else {
				require.NoError(t, err)

				if tc.requireURL {
					require.NotEqual(t, &url.URL{}, targetURL)
				}
			}
		})
	}
}
