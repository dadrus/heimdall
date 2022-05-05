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
		assert func(t *testing.T, err error, audience Audience)
	}{
		{
			uc:   "audience encoded as string",
			json: []byte(`{ "aud": "foo bar baz" }`),
			assert: func(t *testing.T, err error, audience Audience) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, audience, 3)
				assert.Contains(t, audience, "foo")
				assert.Contains(t, audience, "bar")
				assert.Contains(t, audience, "baz")
			},
		},
		{
			uc:   "audience encoded as json array",
			json: []byte(`{ "aud": ["foo", "bar", "baz"] }`),
			assert: func(t *testing.T, err error, audience Audience) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, audience, 3)
				assert.Contains(t, audience, "foo")
				assert.Contains(t, audience, "bar")
				assert.Contains(t, audience, "baz")
			},
		},
		{
			uc:   "bad audience encoding (not a json object)",
			json: []byte(`"aud": ["foo", "bar", "baz"]`),
			assert: func(t *testing.T, err error, audience Audience) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "bad audience encoding (not expected content)",
			json: []byte(`{ "aud": true }`),
			assert: func(t *testing.T, err error, audience Audience) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrConfiguration)
				assert.Contains(t, err.Error(), "unexpected content")
			},
		},
		{
			uc:   "bad audience encoding (not expected json array content)",
			json: []byte(`{ "aud": [true] }`),
			assert: func(t *testing.T, err error, audience Audience) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrConfiguration)
				assert.Contains(t, err.Error(), "audience array")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			var typ Typ

			// WHEN
			err := json.Unmarshal(tc.json, &typ)

			// THEN
			tc.assert(t, err, typ.Audience)
		})
	}
}
