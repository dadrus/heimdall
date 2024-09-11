// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package rules

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/config"
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

func TestCreateHostMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []config.HostMatcher
		assert func(t *testing.T, matcher RouteMatcher, err error)
	}{
		{
			uc: "empty configuration",
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Empty(t, matcher)
			},
		},
		{
			uc:   "valid glob expression",
			conf: []config.HostMatcher{{Value: "/**", Type: "glob"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(compositeMatcher)
				assert.IsType(t, &hostMatcher{}, hms[0])
				assert.IsType(t, &globMatcher{}, hms[0].(*hostMatcher).typedMatcher)
			},
		},
		{
			uc:   "invalid glob expression",
			conf: []config.HostMatcher{{Value: "!*][)(*", Type: "glob"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile host matching expression at index 0")
			},
		},
		{
			uc:   "valid regex expression",
			conf: []config.HostMatcher{{Value: ".*", Type: "regex"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(compositeMatcher)
				assert.IsType(t, &hostMatcher{}, hms[0])
				assert.IsType(t, &regexpMatcher{}, hms[0].(*hostMatcher).typedMatcher)
			},
		},
		{
			uc:   "invalid regex expression",
			conf: []config.HostMatcher{{Value: "?>?<*??", Type: "regex"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile host matching expression at index 0")
			},
		},
		{
			uc:   "exact expression",
			conf: []config.HostMatcher{{Value: "?>?<*??", Type: "exact"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(compositeMatcher)
				assert.IsType(t, &hostMatcher{}, hms[0])
				assert.IsType(t, &exactMatcher{}, hms[0].(*hostMatcher).typedMatcher)
			},
		},
		{
			uc:   "unsupported type",
			conf: []config.HostMatcher{{Value: "foo", Type: "bar"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported host matching expression type 'bar' at index 0")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hm, err := createHostMatcher(tc.conf)

			tc.assert(t, hm, err)
		})
	}
}

func TestCreatePathParamsMatcher(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		conf   []config.ParameterMatcher
		assert func(t *testing.T, matcher RouteMatcher, err error)
	}{
		{
			uc: "empty configuration",
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Empty(t, matcher)
			},
		},
		{
			uc:   "valid glob expression",
			conf: []config.ParameterMatcher{{Name: "foo", Value: "/**", Type: "glob"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(compositeMatcher)
				assert.IsType(t, &pathParamMatcher{}, hms[0])
				assert.IsType(t, &globMatcher{}, hms[0].(*pathParamMatcher).typedMatcher)
			},
		},
		{
			uc:   "invalid glob expression",
			conf: []config.ParameterMatcher{{Name: "foo", Value: "!*][)(*", Type: "glob"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile path params matching expression for parameter 'foo' at index 0")
			},
		},
		{
			uc:   "valid regex expression",
			conf: []config.ParameterMatcher{{Name: "foo", Value: ".*", Type: "regex"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(compositeMatcher)
				assert.IsType(t, &pathParamMatcher{}, hms[0])
				assert.IsType(t, &regexpMatcher{}, hms[0].(*pathParamMatcher).typedMatcher)
			},
		},
		{
			uc:   "invalid regex expression",
			conf: []config.ParameterMatcher{{Name: "foo", Value: "?>?<*??", Type: "regex"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile path params matching expression for parameter 'foo' at index 0")
			},
		},
		{
			uc:   "exact expression",
			conf: []config.ParameterMatcher{{Name: "foo", Value: "?>?<*??", Type: "exact"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, compositeMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(compositeMatcher)
				assert.IsType(t, &pathParamMatcher{}, hms[0])
				assert.IsType(t, &exactMatcher{}, hms[0].(*pathParamMatcher).typedMatcher)
			},
		},
		{
			uc:   "unsupported type",
			conf: []config.ParameterMatcher{{Name: "foo", Value: "foo", Type: "bar"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported path parameter expression type 'bar' for parameter 'foo' at index 0")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			pm, err := createPathParamsMatcher(tc.conf, config.EncodedSlashesOff)

			tc.assert(t, pm, err)
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
		{uc: "does not match", matcher: schemeMatcher("http"), toMatch: "https"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			err := tc.matcher.Matches(
				&heimdall.Request{URL: &heimdall.URL{URL: url.URL{Scheme: tc.toMatch}}},
				nil,
				nil,
			)

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrRequestSchemeMismatch)
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
		{uc: "does not match", matcher: methodMatcher{"GET"}, toMatch: "POST"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			err := tc.matcher.Matches(&heimdall.Request{Method: tc.toMatch}, nil, nil)

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrRequestMethodMismatch)
			}
		})
	}
}

func TestHostMatcherMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		conf    []config.HostMatcher
		toMatch string
		matches bool
	}{
		{uc: "matches any host", conf: []config.HostMatcher{{Value: "**", Type: "glob"}}, toMatch: "foo.example.com", matches: true},
		{uc: "matches", conf: []config.HostMatcher{{Value: "example.com", Type: "exact"}}, toMatch: "example.com", matches: true},
		{uc: "does not match", conf: []config.HostMatcher{{Value: "^example.com", Type: "regex"}}, toMatch: "foo.example.com"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hm, err := createHostMatcher(tc.conf)
			require.NoError(t, err)

			err = hm.Matches(&heimdall.Request{URL: &heimdall.URL{URL: url.URL{Host: tc.toMatch}}}, nil, nil)

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrRequestHostMismatch)
			}
		})
	}
}

func TestPathParamsMatcherMatches(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		conf          []config.ParameterMatcher
		slashHandling config.EncodedSlashesHandling
		toMatch       url.URL
		keys          []string
		values        []string
		matches       bool
	}{
		{
			uc: "parameter not present in keys",
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar"},
			},
			keys:   []string{"bar"},
			values: []string{"baz"},
		},
		{
			uc: "encoded slashes are not allowed",
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar%2Fbaz"},
			},
			slashHandling: config.EncodedSlashesOff,
			keys:          []string{"foo"},
			values:        []string{"bar%2Fbaz"},
			toMatch: func() url.URL {
				uri, err := url.Parse("http://example.com/bar%2Fbaz")
				require.NoError(t, err)

				return *uri
			}(),
		},
		{
			uc: "matches with path having allowed but not decoded encoded slashes",
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar%2Fbaz"},
			},
			slashHandling: config.EncodedSlashesOnNoDecode,
			keys:          []string{"foo"},
			values:        []string{"bar%2Fbaz"},
			toMatch: func() url.URL {
				uri, err := url.Parse("http://example.com/bar%2Fbaz")
				require.NoError(t, err)

				return *uri
			}(),
			matches: true,
		},
		{
			uc: "matches with path having allowed decoded slashes",
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar/baz"},
			},
			slashHandling: config.EncodedSlashesOn,
			keys:          []string{"foo"},
			values:        []string{"bar%2Fbaz"},
			toMatch: func() url.URL {
				uri, err := url.Parse("http://example.com/bar%2Fbaz")
				require.NoError(t, err)

				return *uri
			}(),
			matches: true,
		},
		{
			uc: "doesn't match",
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar"},
			},
			slashHandling: config.EncodedSlashesOn,
			keys:          []string{"foo"},
			values:        []string{"baz"},
			toMatch: func() url.URL {
				uri, err := url.Parse("http://example.com/bar")
				require.NoError(t, err)

				return *uri
			}(),
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hm, err := createPathParamsMatcher(tc.conf, tc.slashHandling)
			require.NoError(t, err)

			err = hm.Matches(&heimdall.Request{URL: &heimdall.URL{URL: tc.toMatch}}, tc.keys, tc.values)

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrRequestPathMismatch)
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
			err := tc.matcher.Matches(
				&heimdall.Request{Method: tc.method, URL: &heimdall.URL{URL: url.URL{Scheme: tc.scheme}}},
				nil,
				nil,
			)

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
