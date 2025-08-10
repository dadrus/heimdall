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

package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClaimsValidate(t *testing.T) {
	t.Parallel()

	dateInTheFuture := NumericDate(time.Now().Add(1 * time.Minute).Unix())
	dateInThePast := NumericDate(time.Now().Add(-1 * time.Minute).Unix())

	for uc, tc := range map[string]struct {
		claims       Claims
		expectations Expectation
		assert       func(t *testing.T, err error)
	}{
		"fails on issuer assertion": {
			claims: Claims{
				Issuer: "foo",
			},
			expectations: Expectation{
				TrustedIssuers: []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "issuer")
			},
		},
		"fails on audience assertion": {
			claims: Claims{
				Issuer:   "foo",
				Audience: Audience{"bar"},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "audience")
			},
		},
		"fails on validity assertion": {
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInTheFuture,
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "valid")
			},
		},
		"fails on issuance time assertion": {
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInTheFuture,
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "issued")
			},
		},
		"fails on scp assertion": {
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scp:       Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"bar", "baz"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "scope")
			},
		},
		"fails on scope assertion": {
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scope:     Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"bar", "baz"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "scope")
			},
		},
		"succeeds using scope claim": {
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scope:     Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"succeeds using scp claim": {
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scp:       Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers: []string{"foo"},
				Audiences:      []string{"bar"},
				ScopesMatcher:  ExactScopeStrategyMatcher{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			err := tc.claims.Validate(tc.expectations)

			// THEN
			tc.assert(t, err)
		})
	}
}
