package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExpectationValidate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		exp    Expectation
		assert func(t *testing.T, err error)
	}{
		{
			uc:  "invalid configuration",
			exp: Expectation{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:  "valid configuration",
			exp: Expectation{TrustedIssuers: []string{"foo"}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.exp.Validate()

			// THEN
			tc.assert(t, err)
		})
	}
}

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

				assert.Error(t, err)
			},
		},
		{
			uc:  "assertion succeeds",
			exp: Expectation{AllowedAlgorithms: []string{"foo"}},
			alg: "foo",
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
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

				assert.Error(t, err)
			},
		},
		{
			uc:     "assertion succeeds",
			exp:    Expectation{TrustedIssuers: []string{"foo"}},
			issuer: "foo",
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
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
			exp:      Expectation{TargetAudiences: []string{"bar"}},
			audience: []string{"foo", "baz"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:       "assertion succeeds",
			exp:      Expectation{TargetAudiences: []string{"foo", "bar"}},
			audience: []string{"foo", "bar"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
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

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter in the future with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{time.Now().Add(-1 * time.Minute), time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter in the future with leeway making the assertion fail",
			exp:   Expectation{ValidityLeeway: -2 * time.Minute},
			times: []time.Time{time.Now().Add(-1 * time.Minute), time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter in the past",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(1 * time.Minute), time.Now().Add(-1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the past with default leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now().Add(-1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the past with disabled leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now().Add(-1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter now with default leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now()},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter now with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{{}, time.Now()},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the future with default leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore not set and notAfter in the future with disabled leeway",
			exp:   Expectation{},
			times: []time.Time{{}, time.Now().Add(1 * time.Minute)},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "both notBefore and notAfter not set",
			exp:   Expectation{},
			times: []time.Time{{}, {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter not set with default leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(-1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the past and notAfter not set with disabled leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(-1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore now and notAfter not set with default leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now(), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore now and notAfter not set with disabled leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now(), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter not set with leeway making assertion success",
			exp:   Expectation{ValidityLeeway: 3 * time.Minute},
			times: []time.Time{time.Now().Add(1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter not set with default leeway",
			exp:   Expectation{},
			times: []time.Time{time.Now().Add(1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:    "notBefore in the future and notAfter not set with disabled leeway",
			exp:   Expectation{ValidityLeeway: 0},
			times: []time.Time{time.Now().Add(1 * time.Minute), {}},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
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

				assert.NoError(t, err)
			},
		},
		{
			uc:   "issued in the past with disabled leeway",
			exp:  Expectation{ValidityLeeway: 0},
			time: time.Now().Add(-1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:   "issued in the past with leeway making it invalid",
			exp:  Expectation{ValidityLeeway: -2 * time.Minute},
			time: time.Now().Add(-1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:   "issued now with default leeway",
			exp:  Expectation{},
			time: time.Now(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:   "issued now with disabled leeway",
			exp:  Expectation{ValidityLeeway: 0},
			time: time.Now(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:   "issued now with leeway making it invalid",
			exp:  Expectation{ValidityLeeway: -1 * time.Minute},
			time: time.Now(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:   "issued in the future with default leeway",
			exp:  Expectation{},
			time: time.Now().Add(1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:   "issued in the future with disabled leeway",
			exp:  Expectation{ValidityLeeway: 0},
			time: time.Now().Add(1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			uc:   "issued now with leeway making it valid",
			exp:  Expectation{ValidityLeeway: 2 * time.Minute},
			time: time.Now().Add(1 * time.Minute),
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc:   "without provided time",
			exp:  Expectation{},
			time: time.Time{},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
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

				assert.NoError(t, err)
			},
		},
		{
			uc:     "scopes don't match",
			exp:    Expectation{ScopesMatcher: ExactScopeStrategyMatcher{"foo", "bar"}},
			scopes: []string{"foo"},
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.Error(t, err)
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
