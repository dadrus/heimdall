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

	"github.com/stretchr/testify/assert"
)

func TestClaimsValidate(t *testing.T) {
	t.Parallel()

	dateInTheFuture := NumericDate(time.Now().Add(1 * time.Minute).Unix())
	dateInThePast := NumericDate(time.Now().Add(-1 * time.Minute).Unix())

	for _, tc := range []struct {
		uc           string
		claims       Claims
		expectations Expectation
		assert       func(t *testing.T, err error)
	}{
		{
			uc: "fails on issuer assertion",
			claims: Claims{
				Issuer: "foo",
			},
			expectations: Expectation{
				TrustedIssuers: []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "issuer")
			},
		},
		{
			uc: "fails on audience assertion",
			claims: Claims{
				Issuer:   "foo",
				Audience: Audience{"bar"},
			},
			expectations: Expectation{
				TrustedIssuers:  []string{"foo"},
				TargetAudiences: []string{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "audience")
			},
		},
		{
			uc: "fails on validity assertion",
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInTheFuture,
			},
			expectations: Expectation{
				TrustedIssuers:  []string{"foo"},
				TargetAudiences: []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "valid")
			},
		},
		{
			uc: "fails on issuance time assertion",
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInTheFuture,
			},
			expectations: Expectation{
				TrustedIssuers:  []string{"foo"},
				TargetAudiences: []string{"bar"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "issued")
			},
		},
		{
			uc: "fails on scp assertion",
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scp:       Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers:  []string{"foo"},
				TargetAudiences: []string{"bar"},
				ScopesMatcher:   ExactScopeStrategyMatcher{"bar", "baz"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "scope")
			},
		},
		{
			uc: "fails on scope assertion",
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scope:     Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers:  []string{"foo"},
				TargetAudiences: []string{"bar"},
				ScopesMatcher:   ExactScopeStrategyMatcher{"bar", "baz"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "scope")
			},
		},
		{
			uc: "succeeds using scope claim",
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scope:     Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers:  []string{"foo"},
				TargetAudiences: []string{"bar"},
				ScopesMatcher:   ExactScopeStrategyMatcher{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc: "succeeds using scp claim",
			claims: Claims{
				Issuer:    "foo",
				Audience:  Audience{"bar"},
				NotBefore: &dateInThePast,
				IssuedAt:  &dateInThePast,
				Scp:       Scopes{"foo", "bar"},
			},
			expectations: Expectation{
				TrustedIssuers:  []string{"foo"},
				TargetAudiences: []string{"bar"},
				ScopesMatcher:   ExactScopeStrategyMatcher{"foo"},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.claims.Validate(tc.expectations)

			// THEN
			tc.assert(t, err)
		})
	}
}
