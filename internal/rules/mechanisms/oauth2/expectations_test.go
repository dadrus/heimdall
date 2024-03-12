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
	"github.com/stretchr/testify/require"
)

func TestExpectationAssertAlgorithm(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		exp    Expectation
		alg    string
		assert func(t *testing.T, err error)
	}{
		{
			uc:  "assertion fails",
			exp: Expectation{AllowedAlgorithms: []string{"bar"}},
			alg: "foo",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:  "assertion succeeds",
			exp: Expectation{AllowedAlgorithms: []string{"foo"}},
			alg: "foo",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.exp.AssertAlgorithm(tc.alg)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestExpectationAssertIssuer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		exp    Expectation
		issuer string
		assert func(t *testing.T, err error)
	}{
		{
			uc:     "assertion fails",
			exp:    Expectation{TrustedIssuers: []string{"bar"}},
			issuer: "foo",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:     "assertion succeeds",
			exp:    Expectation{TrustedIssuers: []string{"foo"}},
			issuer: "foo",
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.exp.AssertIssuer(tc.issuer)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestExpectationAssertAudience(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		exp      Expectation
		audience []string
		assert   func(t *testing.T, err error)
	}{
		{
			uc:       "assertion fails",
			exp:      Expectation{Audiences: []string{"bar"}},
			audience: []string{"foo", "baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:       "assertion succeeds (full intersection)",
			exp:      Expectation{Audiences: []string{"foo", "bar"}},
			audience: []string{"foo", "bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:       "assertion succeeds (partial intersection 1)",
			exp:      Expectation{Audiences: []string{"bar"}},
			audience: []string{"foo", "bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:       "assertion succeeds (partial intersection 2)",
			exp:      Expectation{Audiences: []string{"foo", "bar"}},
			audience: []string{"foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.exp.AssertAudience(tc.audience)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestExpectationAssertValidity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		exp    Expectation
		times  []time.Time
		assert func(t *testing.T, err error)
	}{
		{
			uc:    "notBefore in the past and notAfter in the future with default leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(-1 * time.Minute), time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter in the future with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{time.Now().Add(-1 * time.Minute), time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter in the future with leeway making the assertion fail",
			exp:   Expectation{ValidityLeeway: -2 * time.Minute},
			times: []time.Time{time.Now().Add(-1 * time.Minute), time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter in the past",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(1 * time.Minute), time.Now().Add(-1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the past with default leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now().Add(-1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the past with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{{}, time.Now().Add(-1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter now with default leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now()},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter now with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{{}, time.Now()},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the future with default leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the future with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{{}, time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "both notBefore and notAfter not set",
			exp:   Expectation{},
			times: []time.Time{{}, {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter not set with default leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(-1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter not set with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{time.Now().Add(-1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore now and notAfter not set with default leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now(), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore now and notAfter not set with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{time.Now(), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter not set with leeway making assertion success",
			exp:   Expectation{ValidityLeeway: 3 * time.Minute},
			times: []time.Time{time.Now().Add(1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter not set with default leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter not set with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{time.Now().Add(1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.exp.AssertValidity(tc.times[0], tc.times[1])

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestExpectationAssertIssuanceTime(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		exp    Expectation
		time   time.Time
		assert func(t *testing.T, err error)
	}{
		{
			uc:   "issued in the past with default leeway",
			exp:  Expectation{},
			time: time.Now().Add(-1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:   "issued in the past with disabled leeway",
			exp:  Expectation{ValidityLeeway: 0},
			time: time.Now().Add(-1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:   "issued in the past with leeway making it invalid",
			exp:  Expectation{ValidityLeeway: -2 * time.Minute},
			time: time.Now().Add(-1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "issued now with default leeway",
			exp:  Expectation{},
			time: time.Now(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:   "issued now with disabled leeway",
			exp:  Expectation{ValidityLeeway: 0},
			time: time.Now(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:   "issued now with leeway making it invalid",
			exp:  Expectation{ValidityLeeway: -1 * time.Minute},
			time: time.Now(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "issued in the future with default leeway",
			exp:  Expectation{},
			time: time.Now().Add(1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "issued in the future with disabled leeway",
			exp:  Expectation{ValidityLeeway: 0},
			time: time.Now().Add(1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "issued now with leeway making it valid",
			exp:  Expectation{ValidityLeeway: 2 * time.Minute},
			time: time.Now().Add(1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:   "without provided time",
			exp:  Expectation{},
			time: time.Time{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.exp.AssertIssuanceTime(tc.time)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestExpectationAssertScopes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		exp    Expectation
		scopes []string
		assert func(t *testing.T, err error)
	}{
		{
			uc:     "scopes match",
			exp:    Expectation{ScopesMatcher: ExactScopeStrategyMatcher{"foo", "bar"}},
			scopes: []string{"foo", "bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:     "scopes don't match",
			exp:    Expectation{ScopesMatcher: ExactScopeStrategyMatcher{"foo", "bar"}},
			scopes: []string{"foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.exp.AssertScopes(tc.scopes)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestMergeExpectations(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		target *Expectation
		source *Expectation
		assert func(t *testing.T, merged *Expectation, source *Expectation, target *Expectation)
	}{
		{
			uc:     "with nil target",
			source: &Expectation{},
			assert: func(t *testing.T, merged *Expectation, source *Expectation, _ *Expectation) {
				t.Helper()

				require.Equal(t, source, merged)
			},
		},
		{
			uc: "with empty target",
			source: &Expectation{
				ScopesMatcher:     ExactScopeStrategyMatcher{},
				Audiences:         []string{"foo"},
				TrustedIssuers:    []string{"bar"},
				AllowedAlgorithms: []string{"RS512"},
				ValidityLeeway:    10 * time.Second,
			},
			target: &Expectation{},
			assert: func(t *testing.T, merged *Expectation, source *Expectation, _ *Expectation) {
				t.Helper()

				require.Equal(t, source, merged)
			},
		},
		{
			uc: "with target having only scopes configured",
			source: &Expectation{
				ScopesMatcher:     ExactScopeStrategyMatcher{},
				Audiences:         []string{"foo"},
				TrustedIssuers:    []string{"bar"},
				AllowedAlgorithms: []string{"RS512"},
				ValidityLeeway:    10 * time.Second,
			},
			target: &Expectation{ScopesMatcher: HierarchicScopeStrategyMatcher{}},
			assert: func(t *testing.T, merged *Expectation, source *Expectation, target *Expectation) {
				t.Helper()

				assert.NotEqual(t, source, merged)
				assert.NotEqual(t, source.ScopesMatcher, merged.ScopesMatcher)
				assert.Equal(t, target.ScopesMatcher, merged.ScopesMatcher)
				assert.Equal(t, source.Audiences, merged.Audiences)
				assert.Equal(t, source.TrustedIssuers, merged.TrustedIssuers)
				assert.Equal(t, source.AllowedAlgorithms, merged.AllowedAlgorithms)
				assert.Equal(t, source.ValidityLeeway, merged.ValidityLeeway)
			},
		},
		{
			uc: "with target having scopes and audience configured",
			source: &Expectation{
				ScopesMatcher:     ExactScopeStrategyMatcher{},
				Audiences:         []string{"foo"},
				TrustedIssuers:    []string{"bar"},
				AllowedAlgorithms: []string{"RS512"},
				ValidityLeeway:    10 * time.Second,
			},
			target: &Expectation{
				ScopesMatcher: HierarchicScopeStrategyMatcher{},
				Audiences:     []string{"baz"},
			},
			assert: func(t *testing.T, merged *Expectation, source *Expectation, target *Expectation) {
				t.Helper()

				assert.NotEqual(t, source, merged)
				assert.NotEqual(t, source.ScopesMatcher, merged.ScopesMatcher)
				assert.Equal(t, target.ScopesMatcher, merged.ScopesMatcher)
				assert.NotEqual(t, source.Audiences, merged.Audiences)
				assert.Equal(t, target.Audiences, merged.Audiences)
				assert.Equal(t, source.TrustedIssuers, merged.TrustedIssuers)
				assert.Equal(t, source.AllowedAlgorithms, merged.AllowedAlgorithms)
				assert.Equal(t, source.ValidityLeeway, merged.ValidityLeeway)
			},
		},
		{
			uc: "with target having scopes, audience and trusted issuers configured",
			source: &Expectation{
				ScopesMatcher:     ExactScopeStrategyMatcher{},
				Audiences:         []string{"foo"},
				TrustedIssuers:    []string{"bar"},
				AllowedAlgorithms: []string{"RS512"},
				ValidityLeeway:    10 * time.Second,
			},
			target: &Expectation{
				ScopesMatcher:  HierarchicScopeStrategyMatcher{},
				Audiences:      []string{"baz"},
				TrustedIssuers: []string{"zab"},
			},
			assert: func(t *testing.T, merged *Expectation, source *Expectation, target *Expectation) {
				t.Helper()

				assert.NotEqual(t, source, merged)
				assert.NotEqual(t, source.ScopesMatcher, merged.ScopesMatcher)
				assert.Equal(t, target.ScopesMatcher, merged.ScopesMatcher)
				assert.NotEqual(t, source.Audiences, merged.Audiences)
				assert.Equal(t, target.Audiences, merged.Audiences)
				assert.NotEqual(t, source.TrustedIssuers, merged.TrustedIssuers)
				assert.Equal(t, target.TrustedIssuers, merged.TrustedIssuers)
				assert.Equal(t, source.AllowedAlgorithms, merged.AllowedAlgorithms)
				assert.Equal(t, source.ValidityLeeway, merged.ValidityLeeway)
			},
		},
		{
			uc: "with target having scopes, audience, trusted issuers and allowed algorithms configured",
			source: &Expectation{
				ScopesMatcher:     ExactScopeStrategyMatcher{},
				Audiences:         []string{"foo"},
				TrustedIssuers:    []string{"bar"},
				AllowedAlgorithms: []string{"RS512"},
				ValidityLeeway:    10 * time.Second,
			},
			target: &Expectation{
				ScopesMatcher:     HierarchicScopeStrategyMatcher{},
				Audiences:         []string{"baz"},
				TrustedIssuers:    []string{"zab"},
				AllowedAlgorithms: []string{"BAR128"},
			},
			assert: func(t *testing.T, merged *Expectation, source *Expectation, target *Expectation) {
				t.Helper()

				assert.NotEqual(t, source, merged)
				assert.NotEqual(t, source.ScopesMatcher, merged.ScopesMatcher)
				assert.Equal(t, target.ScopesMatcher, merged.ScopesMatcher)
				assert.NotEqual(t, source.Audiences, merged.Audiences)
				assert.Equal(t, target.Audiences, merged.Audiences)
				assert.NotEqual(t, source.TrustedIssuers, merged.TrustedIssuers)
				assert.Equal(t, target.TrustedIssuers, merged.TrustedIssuers)
				assert.NotEqual(t, source.AllowedAlgorithms, merged.AllowedAlgorithms)
				assert.Equal(t, target.AllowedAlgorithms, merged.AllowedAlgorithms)
				assert.Equal(t, source.ValidityLeeway, merged.ValidityLeeway)
			},
		},
		{
			uc: "with target having everything reconfigured",
			source: &Expectation{
				ScopesMatcher:     ExactScopeStrategyMatcher{},
				Audiences:         []string{"foo"},
				TrustedIssuers:    []string{"bar"},
				AllowedAlgorithms: []string{"RS512"},
				ValidityLeeway:    10 * time.Second,
			},
			target: &Expectation{
				ScopesMatcher:     HierarchicScopeStrategyMatcher{},
				Audiences:         []string{"baz"},
				TrustedIssuers:    []string{"zab"},
				AllowedAlgorithms: []string{"BAR128"},
				ValidityLeeway:    20 * time.Minute,
			},
			assert: func(t *testing.T, merged *Expectation, source *Expectation, target *Expectation) {
				t.Helper()

				assert.NotEqual(t, source, merged)
				assert.NotEqual(t, source.ScopesMatcher, merged.ScopesMatcher)
				assert.Equal(t, target.ScopesMatcher, merged.ScopesMatcher)
				assert.NotEqual(t, source.Audiences, merged.Audiences)
				assert.Equal(t, target.Audiences, merged.Audiences)
				assert.NotEqual(t, source.TrustedIssuers, merged.TrustedIssuers)
				assert.Equal(t, target.TrustedIssuers, merged.TrustedIssuers)
				assert.NotEqual(t, source.AllowedAlgorithms, merged.AllowedAlgorithms)
				assert.Equal(t, target.AllowedAlgorithms, merged.AllowedAlgorithms)
				assert.NotEqual(t, source.ValidityLeeway, merged.ValidityLeeway)
				assert.Equal(t, target.ValidityLeeway, merged.ValidityLeeway)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			exp := tc.target.Merge(tc.source)

			// THEN
			tc.assert(t, &exp, tc.source, tc.target)
		})
	}
}
