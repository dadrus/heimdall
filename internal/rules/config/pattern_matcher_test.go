package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegexPatternMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		expression string
		matches    string
		assert     func(t *testing.T, err error, matched bool)
	}{
		{
			uc: "with empty expression",
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoRegexPatternDefined)
			},
		},
		{
			uc:         "with bad regex expression",
			expression: "?>?<*??",
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "error parsing regexp")
			},
		},
		{
			uc:         "doesn't match",
			expression: "^/foo/(bar|baz)/zab",
			matches:    "/foo/zab/zab",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, matched)
			},
		},
		{
			uc:         "successful",
			expression: "^/foo/(bar|baz)/zab",
			matches:    "/foo/bar/zab",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, matched)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var matched bool

			matcher, err := newRegexMatcher(tc.expression)
			if matcher != nil {
				matched = matcher.match(tc.matches)
			}

			tc.assert(t, err, matched)
		})
	}
}

func TestGlobPatternMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		expression string
		matches    string
		assert     func(t *testing.T, err error, matched bool)
	}{
		{
			uc: "with empty expression",
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoGlobPatternDefined)
			},
		},
		{
			uc:         "with bad glob expression",
			expression: "!*][)(*",
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unexpected end of input")
			},
		},
		{
			uc:         "doesn't match",
			expression: "{/**.foo,/**.bar}",
			matches:    "/foo.baz",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, matched)
			},
		},
		{
			uc:         "successful",
			expression: "{/**.foo,/**.bar}",
			matches:    "/foo.bar",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, matched)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var matched bool

			matcher, err := newGlobMatcher(tc.expression, '/')
			if matcher != nil {
				matched = matcher.match(tc.matches)
			}

			tc.assert(t, err, matched)
		})
	}
}
