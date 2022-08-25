package authenticators

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionConfigCreateSession(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc        string
		data      []byte
		configure func(t *testing.T, conf *SessionConfig)
		assert    func(t *testing.T, session *Session, err error)
	}{
		{
			uc:   "empty session config",
			data: []byte(`{"foo":"bar"}`),
			configure: func(t *testing.T, _ *SessionConfig) {
				t.Helper()
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.naf)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "only active field is defined in session config",
			data: []byte(`{"foo":"false"}`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.ActiveField = "foo"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.False(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.naf)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "only issued at field is defined in session config",
			data: []byte(`{"data": { "val": 1661408890 } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.IssuedAtField = "data.val"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.naf)
				assert.Equal(t, time.Unix(1661408890, 0), session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "issued at and time format fields are defined in session config",
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.IssuedAtField = "data.val"
				conf.TimeFormat = "Mon 02 Jan 2006 15:04:05 MST"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				timeVal, err2 := time.Parse("Mon 02 Jan 2006 15:04:05 MST", "Tue 25 Aug 2022 07:30:15 CET")
				require.NoError(t, err2)

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Time{}, session.naf)
				assert.Equal(t, timeVal, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "issued at and time format fields are defined in session config, with bad time format",
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.IssuedAtField = "data.val"
				conf.TimeFormat = "Fri 02 Jan 2022 15:04:05 MST"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.Nil(t, session)
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSessionParseError)
				assert.Contains(t, err.Error(), "issued_at")
			},
		},
		{
			uc:   "only not before field is defined in session config",
			data: []byte(`{"data": { "val": 1661408890 } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.NotBeforeField = "data.val"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Unix(1661408890, 0), session.nbf)
				assert.Equal(t, time.Time{}, session.naf)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "not before and time format fields are defined in session config",
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.NotBeforeField = "data.val"
				conf.TimeFormat = "Mon 02 Jan 2006 15:04:05 MST"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				timeVal, err2 := time.Parse("Mon 02 Jan 2006 15:04:05 MST", "Tue 25 Aug 2022 07:30:15 CET")
				require.NoError(t, err2)

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, timeVal, session.nbf)
				assert.Equal(t, time.Time{}, session.naf)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "not before and time format fields are defined in session config, with bad time format",
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.NotBeforeField = "data.val"
				conf.TimeFormat = "Fri 02 Jan 2022 15:04:05 MST"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.Nil(t, session)
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSessionParseError)
				assert.Contains(t, err.Error(), "not_before")
			},
		},
		{
			uc:   "only not after field is defined in session config",
			data: []byte(`{"data": { "val": 1661408890 } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.NotAfterField = "data.val"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, time.Unix(1661408890, 0), session.naf)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "not after and time format fields are defined in session config",
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.NotAfterField = "data.val"
				conf.TimeFormat = "Mon 02 Jan 2006 15:04:05 MST"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				timeVal, err2 := time.Parse("Mon 02 Jan 2006 15:04:05 MST", "Tue 25 Aug 2022 07:30:15 CET")
				require.NoError(t, err2)

				require.NoError(t, err)
				require.NotNil(t, session)
				assert.True(t, session.active)
				assert.Equal(t, time.Time{}, session.nbf)
				assert.Equal(t, timeVal, session.naf)
				assert.Equal(t, time.Time{}, session.iat)
				assert.Equal(t, time.Duration(0), session.leeway)
			},
		},
		{
			uc:   "not after and time format fields are defined in session config, with bad time format",
			data: []byte(`{"data": { "val": "Tue 25 Aug 2022 07:30:15 CET" } }`),
			configure: func(t *testing.T, conf *SessionConfig) {
				t.Helper()

				conf.NotAfterField = "data.val"
				conf.TimeFormat = "Fri 02 Jan 2022 15:04:05 MST"
			},
			assert: func(t *testing.T, session *Session, err error) {
				t.Helper()

				require.Nil(t, session)
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSessionParseError)
				assert.Contains(t, err.Error(), "not_after")
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			s := SessionConfig{}
			tc.configure(t, &s)

			// WHEN
			session, err := s.CreateSession(tc.data)

			// THEN
			tc.assert(t, session, err)
		})
	}
}
