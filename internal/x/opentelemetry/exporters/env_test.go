package exporters

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnvOr(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc           string
		key          string
		defaultValue string
		setup        func(t *testing.T)
		assert       func(t *testing.T, value string)
	}{
		{
			uc:           "no env with default",
			key:          "does-not-exist",
			defaultValue: "foobar",
			setup:        func(t *testing.T) { t.Helper() },
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Equal(t, "foobar", value)
			},
		},
		{
			uc:           "set env",
			key:          "TestEnvOr-ExistingKey",
			defaultValue: "foobar",
			setup: func(t *testing.T) {
				t.Helper()
				t.Setenv("TestEnvOr-ExistingKey", "barfoo")
			},
			assert: func(t *testing.T, value string) {
				t.Helper()

				assert.Equal(t, "barfoo", value)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			tc.setup(t)

			// WHEN
			value := envOr(tc.key, tc.defaultValue)

			// THEN
			tc.assert(t, value)
		})
	}
}
