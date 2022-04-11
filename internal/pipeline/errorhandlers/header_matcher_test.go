package errorhandlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		headers  map[string][]string
		match    map[string]string
		matching bool
	}{
		{
			uc: "match single header",
			headers: map[string][]string{
				"foobar": {"foo", "bar"},
			},
			match:    map[string]string{"foobar": "bar"},
			matching: true,
		},
		{
			uc: "match multiple header",
			headers: map[string][]string{
				"foobar":      {"foo", "bar"},
				"some-header": {"value1", "value2"},
			},
			match: map[string]string{
				"foobar":      "bar",
				"some-header": "value1",
			},
			matching: true,
		},
		{
			uc: "don't match header",
			headers: map[string][]string{
				"foobar":      {"foo", "bar"},
				"some-header": {"value1", "value2"},
			},
			match:    map[string]string{"barfoo": "bar"},
			matching: false,
		},
		{
			uc: "don't match header value",
			headers: map[string][]string{
				"foobar":      {"foo", "bar"},
				"some-header": {"value1", "value2"},
			},
			match:    map[string]string{"foobar": "value1"},
			matching: false,
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			matcher := HeaderMatcher(tc.headers)

			// WHEN
			matched := matcher.Match(tc.match)

			// THEN
			assert.Equal(t, tc.matching, matched)
		})
	}
}
