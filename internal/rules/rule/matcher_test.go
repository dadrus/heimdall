package rule

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatcherUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type Typ struct {
		Matcher Matcher `json:"match"`
	}

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, matcher *Matcher)
	}{
		{
			uc:     "specified as string",
			config: []byte(`{ "match": "foo.bar" }`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "glob", matcher.Strategy)
			},
		},
		{
			uc: "specified as structured type with invalid json structure",
			config: []byte(`{
"match": {
  strategy: foo
}
}`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid character")
			},
		},
		{
			uc: "specified as structured type without url",
			config: []byte(`{
"match": {
  "strategy": "foo"
}
}`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), ErrURLMissing.Error())
			},
		},
		{
			uc: "specified as structured type without strategy specified",
			config: []byte(`{
"match": {
  "url": "foo.bar"
}
}`),
			assert: func(t *testing.T, err error, matcher *Matcher) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo.bar", matcher.URL)
				assert.Equal(t, "glob", matcher.Strategy)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var typ Typ

			// WHEN
			err := json.Unmarshal(tc.config, &typ)

			// THEN
			tc.assert(t, err, &typ.Matcher)
		})
	}
}
