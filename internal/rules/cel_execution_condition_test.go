package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCelExecutionCondition(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		expression string
		err        string
	}{
		{uc: "malformed expression", expression: "foobar", err: "failed compiling"},
		{uc: "is not a bool expression", expression: "1", err: "result type error"},
		{uc: "valid expression", expression: "true"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			condition, err := newCelExecutionCondition(tc.expression)

			// THEN
			if len(tc.err) != 0 {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, condition)
				require.NotNil(t, condition.p)
			}
		})
	}
}
