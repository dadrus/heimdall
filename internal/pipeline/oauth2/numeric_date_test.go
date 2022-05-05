package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNumericDateUnmarshalJSON(t *testing.T) {
	t.Parallel()

	type Typ struct {
		Date NumericDate `json:"date,omitempty"`
	}

	for _, tc := range []struct {
		uc     string
		json   []byte
		assert func(t *testing.T, err error, date NumericDate)
	}{
		{
			uc:   "valid config",
			json: []byte(`{ "date": 100 }`),
			assert: func(t *testing.T, err error, date NumericDate) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, int64(100), date.Time().Unix())
			},
		},
		{
			uc:   "invalid config",
			json: []byte(`{ "date": "foo" }`),
			assert: func(t *testing.T, err error, date NumericDate) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to parse")
			},
		},
	} {
		// GIVEN
		var typ Typ

		// WHEN
		err := json.Unmarshal(tc.json, &typ)

		// THEN
		tc.assert(t, err, typ.Date)
	}
}

func TestNumericDateTime(t *testing.T) {
	t.Parallel()

	// GIVEN
	var (
		date1 *NumericDate
		date2 *NumericDate
	)

	date := NumericDate(100)
	date2 = &date

	// WHEN
	time1 := date1.Time()
	time2 := date2.Time()

	// THEN
	assert.Less(t, time1.Unix(), int64(0))
	assert.Equal(t, int64(100), time2.Unix())
}
