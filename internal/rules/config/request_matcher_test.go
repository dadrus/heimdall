package config

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestCreateMethodMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		configured  []string
		expected    methodMatcher
		shouldError bool
	}{
		{
			uc:       "empty configuration",
			expected: methodMatcher{},
		},
		{
			uc:          "empty method in list",
			configured:  []string{"FOO", ""},
			shouldError: true,
		},
		{
			uc:         "duplicates should be removed",
			configured: []string{"BAR", "BAZ", "BAZ", "FOO", "FOO", "ZAB"},
			expected:   methodMatcher{"BAR", "BAZ", "FOO", "ZAB"},
		},
		{
			uc:         "only ALL configured",
			configured: []string{"ALL"},
			expected: methodMatcher{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions,
				http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace,
			},
		},
		{
			uc:         "ALL without POST and TRACE",
			configured: []string{"ALL", "!POST", "!TRACE"},
			expected: methodMatcher{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
				http.MethodOptions, http.MethodPatch, http.MethodPut,
			},
		},
		{
			uc:         "ALL with duplicates and without POST and TRACE",
			configured: []string{"ALL", "GET", "!POST", "!TRACE", "!TRACE"},
			expected: methodMatcher{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
				http.MethodOptions, http.MethodPatch, http.MethodPut,
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			res, err := createMethodMatcher(tc.configured)

			// THEN
			if tc.shouldError {
				require.Error(t, err)
			} else {
				require.Equal(t, tc.expected, res)
			}
		})
	}
}

func TestCreatePathMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		glob   string
		regex  string
		assert func(t *testing.T, mather *pathMatcher, err error)
	}{
		{
			uc: "empty configuration",
			assert: func(t *testing.T, mather *pathMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, alwaysMatcher{}, mather.patternMatcher)
			},
		},
		{
			uc:   "valid glob expression",
			glob: "/**",
			assert: func(t *testing.T, mather *pathMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &globMatcher{}, mather.patternMatcher)
			},
		},
		{
			uc:   "invalid glob expression",
			glob: "!*][)(*",
			assert: func(t *testing.T, _ *pathMatcher, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:    "valid regex expression",
			regex: ".*",
			assert: func(t *testing.T, mather *pathMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &regexpMatcher{}, mather.patternMatcher)
			},
		},
		{
			uc:    "invalid regex expression",
			regex: "?>?<*??",
			assert: func(t *testing.T, _ *pathMatcher, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hm, err := createPathMatcher(tc.glob, tc.regex, EncodedSlashesOnNoDecode)

			tc.assert(t, hm, err)
		})
	}
}

func TestCreateHostMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		glob   string
		regex  string
		assert func(t *testing.T, mather *hostMatcher, err error)
	}{
		{
			uc: "empty configuration",
			assert: func(t *testing.T, mather *hostMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, alwaysMatcher{}, mather.patternMatcher)
			},
		},
		{
			uc:   "valid glob expression",
			glob: "/**",
			assert: func(t *testing.T, mather *hostMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &globMatcher{}, mather.patternMatcher)
			},
		},
		{
			uc:   "invalid glob expression",
			glob: "!*][)(*",
			assert: func(t *testing.T, _ *hostMatcher, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:    "valid regex expression",
			regex: ".*",
			assert: func(t *testing.T, mather *hostMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &regexpMatcher{}, mather.patternMatcher)
			},
		},
		{
			uc:    "invalid regex expression",
			regex: "?>?<*??",
			assert: func(t *testing.T, _ *hostMatcher, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hm, err := createHostMatcher(tc.glob, tc.regex)

			tc.assert(t, hm, err)
		})
	}
}

func TestSchemeMatcherMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		matcher schemeMatcher
		toMatch string
		matches bool
	}{
		{uc: "matches any schemes", matcher: schemeMatcher(""), toMatch: "foo", matches: true},
		{uc: "matches", matcher: schemeMatcher("http"), toMatch: "http", matches: true},
		{uc: "does not match", matcher: schemeMatcher("http"), toMatch: "https", matches: false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			err := tc.matcher.Matches(&heimdall.Request{URL: &heimdall.URL{URL: url.URL{Scheme: tc.toMatch}}})

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestMethodMatcherMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		matcher methodMatcher
		toMatch string
		matches bool
	}{
		{uc: "matches any methods", matcher: methodMatcher{}, toMatch: "GET", matches: true},
		{uc: "matches", matcher: methodMatcher{"GET"}, toMatch: "GET", matches: true},
		{uc: "does not match", matcher: methodMatcher{"GET"}, toMatch: "POST", matches: false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			err := tc.matcher.Matches(&heimdall.Request{Method: tc.toMatch})

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestHostMatcherMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		expression string
		toMatch    string
		matches    bool
	}{
		{uc: "matches any host", expression: "**", toMatch: "foo.example.com", matches: true},
		{uc: "matches", expression: "example.com", toMatch: "example.com", matches: true},
		{uc: "does not match", expression: "example.com", toMatch: "foo.example.com", matches: false},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hm, err := createHostMatcher(tc.expression, "")
			require.NoError(t, err)

			err = hm.Matches(&heimdall.Request{URL: &heimdall.URL{URL: url.URL{Host: tc.toMatch}}})

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestPathMatcherMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		expression    string
		slashEncoding EncodedSlashesHandling
		toMatch       string
		matches       bool
	}{
		{
			uc:            "matches any path",
			slashEncoding: EncodedSlashesOn,
			toMatch:       "foo.example.com",
			matches:       true,
		},
		{
			uc:            "matches path containing encoded slash with slash encoding on",
			expression:    "/foo/bar/*",
			slashEncoding: EncodedSlashesOn,
			toMatch:       "foo%2Fbar/baz",
			matches:       true,
		},
		{
			uc:            "matches path containing encoded slash without slash decoding",
			expression:    "/foo%2Fbar/*",
			slashEncoding: EncodedSlashesOnNoDecode,
			toMatch:       "foo%2Fbar/baz",
			matches:       true,
		},
		{
			uc:            "does not match path containing encoded slash with slash encoding on",
			expression:    "foo/bar",
			slashEncoding: EncodedSlashesOn,
			toMatch:       "foo%2Fbar/baz",
			matches:       false,
		},
		{
			uc:            "does not match path containing encoded slash without slash encoding",
			expression:    "foo%2Fbar",
			slashEncoding: EncodedSlashesOnNoDecode,
			toMatch:       "foo%2Fbar/baz",
			matches:       false,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hm, err := createPathMatcher(tc.expression, "", tc.slashEncoding)
			require.NoError(t, err)

			uri, err := url.Parse("https://example.com/" + tc.toMatch)
			require.NoError(t, err)

			err = hm.Matches(&heimdall.Request{URL: &heimdall.URL{URL: *uri}})

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestCompositeMatcherMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		matcher compositeMatcher
		method  string
		scheme  string
		matches bool
	}{
		{
			uc:      "matches anything",
			matcher: compositeMatcher{},
			method:  "GET",
			scheme:  "foo",
			matches: true,
		},
		{
			uc:      "matches",
			matcher: compositeMatcher{methodMatcher{"GET"}, schemeMatcher("https")},
			method:  "GET",
			scheme:  "https",
			matches: true,
		},
		{
			uc:      "does not match",
			matcher: compositeMatcher{methodMatcher{"POST"}},
			method:  "GET",
			scheme:  "https",
			matches: false,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			err := tc.matcher.Matches(&heimdall.Request{Method: tc.method, URL: &heimdall.URL{URL: url.URL{Scheme: tc.scheme}}})

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
