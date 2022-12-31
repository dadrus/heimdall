package rulesetparser

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

func TestParseRules(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		contentType string
		content     []byte
		assert      func(t *testing.T, err error, rules []rule.Configuration)
	}{
		{
			uc:          "unsupported content type and not empty contents",
			contentType: "foobar",
			content:     []byte(`foo: bar`),
			assert: func(t *testing.T, err error, rules []rule.Configuration) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "unsupported 'foobar'")
			},
		},
		{
			uc:          "unsupported content type and empty contents",
			contentType: "foobar",
			assert: func(t *testing.T, err error, rules []rule.Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, rules)
			},
		},
		{
			uc:          "JSON content and not empty contents",
			contentType: "application/json",
			content:     []byte(`[{"id": "bar"}]`),
			assert: func(t *testing.T, err error, rules []rule.Configuration) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:          "JSON content and empty contents",
			contentType: "application/json",
			assert: func(t *testing.T, err error, rules []rule.Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, rules)
			},
		},
		{
			uc:          "YAML content and not empty contents",
			contentType: "application/yaml",
			content:     []byte(`- id: bar`),
			assert: func(t *testing.T, err error, rules []rule.Configuration) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc:          "YAML content and empty contents",
			contentType: "application/yaml",
			assert: func(t *testing.T, err error, rules []rule.Configuration) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, rules)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			rules, err := ParseRules(tc.contentType, bytes.NewBuffer(tc.content))

			// THEN
			tc.assert(t, err, rules)
		})
	}
}
