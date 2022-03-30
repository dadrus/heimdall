package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidityAssertion(t *testing.T) {
	for _, tc := range []struct {
		uc         string
		validities []int64
		assert     func(t *testing.T, err error)
	}{
		{
			uc:         "no nbf and exp",
			validities: []int64{-1, -1},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "no nbf, but exp in the past",
			validities: []int64{-1, time.Now().Unix() - 2},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "no nbf, but exp in the future",
			validities: []int64{-1, time.Now().Unix() + 2},
			assert:     func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			uc:         "no nbf, but exp now",
			validities: []int64{-1, time.Now().Unix()},
			assert:     func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			uc:         "nbf in the past, but no exp",
			validities: []int64{time.Now().Unix() - 2, -1},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf in the past, exp in the past",
			validities: []int64{time.Now().Unix() - 2, time.Now().Unix() - 2},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf in the past, exp in the future",
			validities: []int64{time.Now().Unix() - 2, time.Now().Unix() + 2},
			assert:     func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			uc:         "nbf in the past, exp now",
			validities: []int64{time.Now().Unix() - 2, time.Now().Unix()},
			assert:     func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			uc:         "nbf in the future, but no exp",
			validities: []int64{time.Now().Unix() + 2, -1},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf in the future, exp in the past",
			validities: []int64{time.Now().Unix() + 2, time.Now().Unix() - 2},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf in the future, exp in the future",
			validities: []int64{time.Now().Unix() + 2, time.Now().Unix() + 2},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf in the future, exp now",
			validities: []int64{time.Now().Unix() + 2, time.Now().Unix()},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf now, but no exp",
			validities: []int64{time.Now().Unix(), -1},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf now, exp in the past",
			validities: []int64{time.Now().Unix(), time.Now().Unix() - 2},
			assert:     func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:         "nbf now, exp in the future",
			validities: []int64{time.Now().Unix(), time.Now().Unix() + 2},
			assert:     func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			uc:         "nbf now, exp now",
			validities: []int64{time.Now().Unix(), time.Now().Unix()},
			assert:     func(t *testing.T, err error) { assert.NoError(t, err) },
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			a := &Expectation{}

			// WHEN
			err := a.AssertValidity(tc.validities[0], tc.validities[1])

			// THEN
			tc.assert(t, err)
		})
	}
}
