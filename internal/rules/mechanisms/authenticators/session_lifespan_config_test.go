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

package authenticators

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionLifespanConfigCreateSession(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		data      []byte
		configure func(t *testing.T, conf *SessionLifespanConfig)
		assert    func(t *testing.T, session *SessionLifespan, err error)
	}{
		"empty session config": {
			data: []byte(`{"foo":"bar"}`),
			configure: func(t *testing.T, _ *SessionLifespanConfig) {
				t.Helper()
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.exp)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"only active field is defined in session config": {
			data: []byte(`{"foo":"false"}`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.ActiveField = "foo"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.False(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.exp)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"only issued at field is defined in session config": {
			data: []byte(`{"data": { "val": 1661408890 } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.IssuedAtField = "data.val"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.exp)
				assert.Equal(t, time.Unix(1661408890, 0), session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"issued at and time format fields are defined in session config": {
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.IssuedAtField = "data.val"
				conf.TimeFormat = "Mon 02 Jan 2006 15:04:05 MST"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				timeVal, err2 := time.Parse("Mon 02 Jan 2006 15:04:05 MST", "Tue 25 Aug 2022 07:30:15 CET")
				require.NoError(t, err2)

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.exp)
				assert.Equal(t, timeVal, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"issued at and time format fields are defined in session config, with bad time format": {
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.IssuedAtField = "data.val"
				conf.TimeFormat = "Fri 02 Jan 2022 15:04:05 MST"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.Nil(t, session)
				require.Error(t, err)
				require.ErrorIs(t, err, ErrSessionLifespanParseError)
				require.ErrorContains(t, err, "issued_at")
			},
		},
		"only not before field is defined in session config": {
			data: []byte(`{"data": { "val": 1661408890 } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.NotBeforeField = "data.val"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Unix(1661408890, 0), session.nbf)
				assert.Equal(t, time.Time{}, session.exp)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"not before and time format fields are defined in session config": {
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.NotBeforeField = "data.val"
				conf.TimeFormat = "Mon 02 Jan 2006 15:04:05 MST"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				timeVal, err2 := time.Parse("Mon 02 Jan 2006 15:04:05 MST", "Tue 25 Aug 2022 07:30:15 CET")
				require.NoError(t, err2)

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, timeVal, session.nbf)
				assert.Equal(t, time.Time{}, session.exp)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"not before and time format fields are defined in session config, with bad time format": {
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.NotBeforeField = "data.val"
				conf.TimeFormat = "Fri 02 Jan 2022 15:04:05 MST"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.Nil(t, session)
				require.Error(t, err)
				require.ErrorIs(t, err, ErrSessionLifespanParseError)
				require.ErrorContains(t, err, "not_before")
			},
		},
		"only not after field is defined in session config": {
			data: []byte(`{"data": { "val": 1661408890 } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.NotAfterField = "data.val"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Unix(1661408890, 0), session.exp) //nolint:testifylint
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"not after and time format fields are defined in session config": {
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.NotAfterField = "data.val"
				conf.TimeFormat = "Mon 02 Jan 2006 15:04:05 MST"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				timeVal, err2 := time.Parse("Mon 02 Jan 2006 15:04:05 MST", "Tue 25 Aug 2022 07:30:15 CET")
				require.NoError(t, err2)

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, timeVal, session.exp) //nolint:testifylint
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		"not after and time format fields are defined in session config, with bad time format": {
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionLifespanConfig) {
				t.Helper()

				conf.NotAfterField = "data.val"
				conf.TimeFormat = "Fri 02 Jan 2022 15:04:05 MST"
			},
			assert: func(t *testing.T, session *SessionLifespan, err error) {
				t.Helper()

				require.Nil(t, session)
				require.Error(t, err)
				require.ErrorIs(t, err, ErrSessionLifespanParseError)
				require.ErrorContains(t, err, "not_after")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			s := SessionLifespanConfig{}
			tc.configure(t, &s)

			// WHEN
			session, err := s.CreateSessionLifespan(tc.data)

			// THEN
			tc.assert(t, session, err)
		})
	}
}
