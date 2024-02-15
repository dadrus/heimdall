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
			assert: func(t *testing.T, err error, _ Audience) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "bad audience encoding (not expected content)",
			json: []byte(`{ "aud": true }`),
			assert: func(t *testing.T, err error, _ Audience) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "unexpected content")
			},
		},
		{
			uc:   "bad audience encoding (not expected json array content)",
			json: []byte(`{ "aud": [true] }`),
			assert: func(t *testing.T, err error, _ Audience) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
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
