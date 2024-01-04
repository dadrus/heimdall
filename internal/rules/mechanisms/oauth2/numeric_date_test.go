// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
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
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
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
