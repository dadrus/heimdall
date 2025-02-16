// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
		createRequest  func(t *testing.T) *http.Request
		configureMocks func(t *testing.T, ctx *mocks2.RequestContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock)
		assertResponse func(t *testing.T, err error, response *http.Response)
	}{
		{
			uc:     "no matching rules",
			expErr: heimdall.ErrNoRuleFound,
			configureMocks: func(t *testing.T, ctx *mocks2.RequestContextMock, repo *mocks4.RepositoryMock, _ *mocks4.RuleMock) {
				t.Helper()

				req := &heimdall.Request{Method: http.MethodPost, URL: &heimdall.URL{URL: *matchingURL}}

				ctx.EXPECT().Context().Return(t.Context())
				ctx.EXPECT().Request().Return(req)
				repo.EXPECT().FindRule(ctx).Return(nil, heimdall.ErrNoRuleFound)
			},
		},
		{
			uc:     "rule execution fails with authentication error",
			expErr: heimdall.ErrAuthentication,
			configureMocks: func(t *testing.T, ctx *mocks2.RequestContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				req := &heimdall.Request{Method: http.MethodGet, URL: &heimdall.URL{URL: *matchingURL}}

				ctx.EXPECT().Context().Return(t.Context())
				ctx.EXPECT().Request().Return(req)
				repo.EXPECT().FindRule(ctx).Return(rule, nil)
				rule.EXPECT().Execute(ctx).Return(nil, heimdall.ErrAuthentication)
			},
		},
		{
			uc: "rule execution succeeds",
			configureMocks: func(t *testing.T, ctx *mocks2.RequestContextMock, repo *mocks4.RepositoryMock, rule *mocks4.RuleMock) {
				t.Helper()

				upstream := mocks4.NewBackendMock(t)
				req := &heimdall.Request{Method: http.MethodGet, URL: &heimdall.URL{URL: *matchingURL}}

				ctx.EXPECT().Context().Return(t.Context())
				ctx.EXPECT().Request().Return(req)
				repo.EXPECT().FindRule(ctx).Return(rule, nil)
				rule.EXPECT().Execute(ctx).Return(upstream, nil)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			repo := mocks4.NewRepositoryMock(t)
			rule := mocks4.NewRuleMock(t)
			ctx := mocks2.NewRequestContextMock(t)

			tc.configureMocks(t, ctx, repo, rule)

			exec := newRuleExecutor(repo)

			// WHEN
			mut, err := exec.Execute(ctx)

			// THEN
			if tc.expErr != nil {
				require.ErrorIs(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, mut)
			}
		})
	}
}
