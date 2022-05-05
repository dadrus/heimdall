package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopesUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type Typ struct {
		Scope Scopes `json:"scope,omitempty"`
	}

	for _, tc := range []struct {
		uc     string
		json   []byte
		assert func(t *testing.T, scopes Scopes)
	}{
		{
			uc:   "scopes encoded as string",
			json: []byte(`{ "scope": "foo bar baz" }`),
			assert: func(t *testing.T, scopes Scopes) {
				t.Helper()

				assert.Len(t, scopes, 3)
				assert.Contains(t, scopes, "foo")
				assert.Contains(t, scopes, "bar")
				assert.Contains(t, scopes, "baz")
			},
		},
		{
			uc:   "scopes encoded as json array",
			json: []byte(`{ "scope": ["foo", "bar", "baz"] }`),
			assert: func(t *testing.T, scopes Scopes) {
				t.Helper()

				assert.Len(t, scopes, 3)
				assert.Contains(t, scopes, "foo")
				assert.Contains(t, scopes, "bar")
				assert.Contains(t, scopes, "baz")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Typ

			// WHEN
			err := json.Unmarshal(tc.json, &typ)

			// THEN
			require.NoError(t, err)
			tc.assert(t, typ.Scope)
		})
	}
}
