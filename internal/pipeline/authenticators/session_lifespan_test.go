package authenticators

import (
	"testing"
	"time"

	"github.com/instana/testify/require"
	"github.com/stretchr/testify/assert"
)

func TestSessionLifespanAssert(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		lifespan *SessionLifespan
		assert   func(t *testing.T, err error)
	}{
		{
			uc:       "session not active",
			lifespan: &SessionLifespan{active: false},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSessionValidity)
				assert.Contains(t, err.Error(), "not active")
			},
		},
		{
			uc:       "nothing configured",
			lifespan: &SessionLifespan{active: true}, // true is default when the object is created by its factory
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "active session with only issued at set to the past",
			lifespan: &SessionLifespan{
				active: true,
				iat:    time.Now().Add(-1 * time.Hour),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "active session with only issued at set to the future",
			lifespan: &SessionLifespan{
				active: true,
				iat:    time.Now().Add(1 * time.Hour),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSessionValidity)
				assert.Contains(t, err.Error(), "issued in the future")
			},
		},
		{
			uc: "active session with only not before set to the past",
			lifespan: &SessionLifespan{
				active: true,
				nbf:    time.Now().Add(-1 * time.Hour),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "active session with only not before set to the future",
			lifespan: &SessionLifespan{
				active: true,
				nbf:    time.Now().Add(1 * time.Hour),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSessionValidity)
				assert.Contains(t, err.Error(), "not yet valid")
			},
		},
		{
			uc: "active session with only not after set to the past",
			lifespan: &SessionLifespan{
				active: true,
				naf:    time.Now().Add(-1 * time.Hour),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSessionValidity)
				assert.Contains(t, err.Error(), "expired")
			},
		},
		{
			uc: "active session with only not after set to the past",
			lifespan: &SessionLifespan{
				active: true,
				naf:    time.Now().Add(1 * time.Hour),
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			err := tc.lifespan.Assert()

			// THEN
			tc.assert(t, err)
		})
	}
}
