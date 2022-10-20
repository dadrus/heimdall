package rulesetparser

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
)

func TestParseJSON(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []byte
		assert func(t *testing.T, err error, ruleSet []config.RuleConfig)
	}{
		{
			uc: "empty rule set spec",
			assert: func(t *testing.T, err error, ruleSet []config.RuleConfig) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, ruleSet)
			},
		},
		{
			uc:   "invalid rule set spec",
			conf: []byte(`[{"foo": "bar"}]`),
			assert: func(t *testing.T, err error, ruleSet []config.RuleConfig) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "valid rule set spec",
			conf: []byte(`[{"id": "bar"}]`),
			assert: func(t *testing.T, err error, ruleSet []config.RuleConfig) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ruleSet, 1)
				assert.Equal(t, "bar", ruleSet[0].ID)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			ruleSet, err := ParseJSON(bytes.NewBuffer(tc.conf))

			// THEN
			tc.assert(t, err, ruleSet)
		})
	}
}
