package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAudienceUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type Typ struct {
		Audience Audience `json:"aud,omitempty"`
	}

	for _, tc := range []struct {
		uc     string
		json   []byte
		assert func(t *testing.T, audience Audience)
	}{
		{
			uc:   "audience encoded as string",
			json: []byte(`{ "aud": "foo bar baz" }`),
			assert: func(t *testing.T, audience Audience) {
				t.Helper()

				assert.Len(t, audience, 3)
				assert.Contains(t, audience, "foo")
				assert.Contains(t, audience, "bar")
				assert.Contains(t, audience, "baz")
			},
		},
		{
			uc:   "audience encoded as json array",
			json: []byte(`{ "aud": ["foo", "bar", "baz"] }`),
			assert: func(t *testing.T, audience Audience) {
				t.Helper()

				assert.Len(t, audience, 3)
				assert.Contains(t, audience, "foo")
				assert.Contains(t, audience, "bar")
				assert.Contains(t, audience, "baz")
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
			tc.assert(t, typ.Audience)
		})
	}
}
