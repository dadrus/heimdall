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

	for uc, tc := range map[string]struct {
		configured  []string
		expected    methodMatcher
		shouldError bool
	}{
		"empty configuration": {
			expected: methodMatcher{},
		},
		"empty method in list": {
			configured:  []string{"FOO", ""},
			shouldError: true,
		},
		"duplicates should be removed": {
			configured: []string{"BAR", "BAZ", "BAZ", "FOO", "FOO", "ZAB"},
			expected:   methodMatcher{"BAR", "BAZ", "FOO", "ZAB"},
		},
		"only ALL configured": {
			configured: []string{"ALL"},
			expected: methodMatcher{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions,
				http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace,
			},
		},
		"ALL without POST and TRACE": {
			configured: []string{"ALL", "!POST", "!TRACE"},
			expected: methodMatcher{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
				http.MethodOptions, http.MethodPatch, http.MethodPut,
			},
		},
		"ALL with duplicates and without POST and TRACE": {
			configured: []string{"ALL", "GET", "!POST", "!TRACE", "!TRACE"},
			expected: methodMatcher{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
				http.MethodOptions, http.MethodPatch, http.MethodPut,
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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

	for uc, tc := range map[string]struct {
		conf   []config.HostMatcher
		assert func(t *testing.T, matcher RouteMatcher, err error)
	}{
		"empty configuration": {
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)

				assert.IsType(t, orMatcher{}, matcher)
				assert.Empty(t, matcher)
			},
		},
		"valid glob expression": {
			conf: []config.HostMatcher{{Value: "/**", Type: "glob"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, orMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(orMatcher)
				assert.IsType(t, &hostMatcher{}, hms[0])
				assert.IsType(t, &globMatcher{}, hms[0].(*hostMatcher).typedMatcher)
			},
		},
		"invalid glob expression": {
			conf: []config.HostMatcher{{Value: "!*][)(*", Type: "glob"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile host matching expression at index 0")
			},
		},
		"valid regex expression": {
			conf: []config.HostMatcher{{Value: ".*", Type: "regex"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, orMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(orMatcher)
				assert.IsType(t, &hostMatcher{}, hms[0])
				assert.IsType(t, &regexpMatcher{}, hms[0].(*hostMatcher).typedMatcher)
			},
		},
		"invalid regex expression": {
			conf: []config.HostMatcher{{Value: "?>?<*??", Type: "regex"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile host matching expression at index 0")
			},
		},
		"exact expression": {
			conf: []config.HostMatcher{{Value: "?>?<*??", Type: "exact"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, orMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(orMatcher)
				assert.IsType(t, &hostMatcher{}, hms[0])
				assert.IsType(t, &exactMatcher{}, hms[0].(*hostMatcher).typedMatcher)
			},
		},
		"unsupported type": {
			conf: []config.HostMatcher{{Value: "foo", Type: "bar"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported host matching expression type 'bar' at index 0")
			},
		},
		"multiple expressions": {
			conf: []config.HostMatcher{
				{Value: "foo", Type: "exact"},
				{Value: ".*", Type: "regex"},
				{Value: "/**", Type: "glob"},
			},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, orMatcher{}, matcher)
				assert.Len(t, matcher, 3)

				hms := matcher.(orMatcher)
				assert.IsType(t, &hostMatcher{}, hms[0])
				assert.IsType(t, &exactMatcher{}, hms[0].(*hostMatcher).typedMatcher)
				assert.IsType(t, &hostMatcher{}, hms[1])
				assert.IsType(t, &regexpMatcher{}, hms[1].(*hostMatcher).typedMatcher)
				assert.IsType(t, &hostMatcher{}, hms[2])
				assert.IsType(t, &globMatcher{}, hms[2].(*hostMatcher).typedMatcher)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			hm, err := createHostMatcher(tc.conf)

			tc.assert(t, hm, err)
		})
	}
}

func TestCreatePathParamsMatcher(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf   []config.ParameterMatcher
		assert func(t *testing.T, matcher RouteMatcher, err error)
	}{
		"empty configuration": {
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, andMatcher{}, matcher)
				assert.Empty(t, matcher)
			},
		},
		"valid glob expression": {
			conf: []config.ParameterMatcher{{Name: "foo", Value: "/**", Type: "glob"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, andMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(andMatcher)
				assert.IsType(t, &pathParamMatcher{}, hms[0])
				assert.IsType(t, &globMatcher{}, hms[0].(*pathParamMatcher).typedMatcher)
			},
		},
		"invalid glob expression": {
			conf: []config.ParameterMatcher{{Name: "foo", Value: "!*][)(*", Type: "glob"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile path params matching expression for parameter 'foo' at index 0")
			},
		},
		"valid regex expression": {
			conf: []config.ParameterMatcher{{Name: "foo", Value: ".*", Type: "regex"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, andMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(andMatcher)
				assert.IsType(t, &pathParamMatcher{}, hms[0])
				assert.IsType(t, &regexpMatcher{}, hms[0].(*pathParamMatcher).typedMatcher)
			},
		},
		"invalid regex expression": {
			conf: []config.ParameterMatcher{{Name: "foo", Value: "?>?<*??", Type: "regex"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to compile path params matching expression for parameter 'foo' at index 0")
			},
		},
		"exact expression": {
			conf: []config.ParameterMatcher{{Name: "foo", Value: "?>?<*??", Type: "exact"}},
			assert: func(t *testing.T, matcher RouteMatcher, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, andMatcher{}, matcher)
				assert.Len(t, matcher, 1)

				hms := matcher.(andMatcher)
				assert.IsType(t, &pathParamMatcher{}, hms[0])
				assert.IsType(t, &exactMatcher{}, hms[0].(*pathParamMatcher).typedMatcher)
			},
		},
		"unsupported type": {
			conf: []config.ParameterMatcher{{Name: "foo", Value: "foo", Type: "bar"}},
			assert: func(t *testing.T, _ RouteMatcher, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported path parameter expression type 'bar' for parameter 'foo' at index 0")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			pm, err := createPathParamsMatcher(tc.conf, config.EncodedSlashesOff)

			tc.assert(t, pm, err)
		})
	}
}

func TestSchemeMatcherMatches(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		matcher schemeMatcher
		toMatch string
		matches bool
	}{
		"matches any schemes": {matcher: schemeMatcher(""), toMatch: "foo", matches: true},
		"matches":             {matcher: schemeMatcher("http"), toMatch: "http", matches: true},
		"does not match":      {matcher: schemeMatcher("http"), toMatch: "https"},
	} {
		t.Run(uc, func(t *testing.T) {
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

	for uc, tc := range map[string]struct {
		matcher methodMatcher
		toMatch string
		matches bool
	}{
		"matches any methods": {matcher: methodMatcher{}, toMatch: "GET", matches: true},
		"matches":             {matcher: methodMatcher{"GET"}, toMatch: "GET", matches: true},
		"does not match":      {matcher: methodMatcher{"GET"}, toMatch: "POST"},
	} {
		t.Run(uc, func(t *testing.T) {
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

	for uc, tc := range map[string]struct {
		conf    []config.HostMatcher
		toMatch string
		matches bool
	}{
		"matches any host in requests": {
			conf:    []config.HostMatcher{{Value: "**", Type: "glob"}},
			toMatch: "foo.example.com",
			matches: true,
		},
		"matches single exact value": {
			conf:    []config.HostMatcher{{Value: "example.com", Type: "exact"}},
			toMatch: "example.com",
			matches: true,
		},
		"matches host from request if multiple matches are defined and one is appropriate": {
			conf: []config.HostMatcher{
				{Value: "foo.com", Type: "exact"},
				{Value: "example.com", Type: "exact"},
			},
			toMatch: "example.com",
			matches: true,
		},
		"does not match single regex based value": {
			conf:    []config.HostMatcher{{Value: "^example.com", Type: "regex"}},
			toMatch: "foo.example.com",
		},
		"does not match if multiple values are defined, but none of them are appropriate": {
			conf: []config.HostMatcher{
				{Value: "foo.com", Type: "exact"},
				{Value: "bar.com", Type: "exact"},
			},
			toMatch: "example.com",
		},
	} {
		t.Run(uc, func(t *testing.T) {
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

	for uc, tc := range map[string]struct {
		conf          []config.ParameterMatcher
		slashHandling config.EncodedSlashesHandling
		toMatch       string
		keys          []string
		values        []string
		matches       bool
	}{
		"parameter not present in keys": {
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar"},
			},
			keys:   []string{"bar"},
			values: []string{"baz"},
		},
		"encoded slashes are not allowed": {
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar%2Fbaz"},
			},
			slashHandling: config.EncodedSlashesOff,
			keys:          []string{"foo"},
			values:        []string{"bar%2Fbaz"},
			toMatch:       "http://example.com/bar%2Fbaz",
		},
		"matches with path having allowed but not decoded encoded slashes": {
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar%2Fbaz[id]"},
			},
			slashHandling: config.EncodedSlashesOnNoDecode,
			keys:          []string{"foo"},
			values:        []string{"bar%2Fbaz%5Bid%5D"},
			toMatch:       "http://example.com/bar%2Fbaz%5Bid%5D",
			matches:       true,
		},
		"matches with path having allowed decoded slashes": {
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar/baz[id]"},
			},
			slashHandling: config.EncodedSlashesOn,
			keys:          []string{"foo"},
			values:        []string{"bar%2Fbaz%5Bid%5D"},
			toMatch:       "http://example.com/foo%2Fbaz%5Bid%5D",
			matches:       true,
		},
		"does not match the request path if appropriate matcher is not defined as first element": {
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar/foo"},
				{Name: "foo", Type: "exact", Value: "bar/bar"},
			},
			slashHandling: config.EncodedSlashesOn,
			keys:          []string{"foo"},
			values:        []string{"bar/bar"},
			toMatch:       "http://example.com/foo/bar",
			matches:       false,
		},
		"doesn't match": {
			conf: []config.ParameterMatcher{
				{Name: "foo", Type: "exact", Value: "bar"},
			},
			slashHandling: config.EncodedSlashesOn,
			keys:          []string{"foo"},
			values:        []string{"baz"},
			toMatch:       "http://example.com/bar",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			hm, err := createPathParamsMatcher(tc.conf, tc.slashHandling)
			require.NoError(t, err)

			uri, err := url.Parse(tc.toMatch)
			require.NoError(t, err)

			err = hm.Matches(&heimdall.Request{URL: &heimdall.URL{URL: *uri}}, tc.keys, tc.values)

			if tc.matches {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrRequestPathMismatch)
			}
		})
	}
}

func TestAndMatcherMatches(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		matcher andMatcher
		method  string
		scheme  string
		matches bool
	}{
		"matches anything": {
			matcher: andMatcher{},
			method:  "GET",
			scheme:  "foo",
			matches: true,
		},
		"matches": {
			matcher: andMatcher{methodMatcher{"GET"}, schemeMatcher("https")},
			method:  "GET",
			scheme:  "https",
			matches: true,
		},
		"does not match": {
			matcher: andMatcher{methodMatcher{"POST"}},
			method:  "GET",
			scheme:  "https",
			matches: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
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

func TestOrMatcherMatches(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		matcher orMatcher
		method  string
		scheme  string
		matches bool
	}{
		"matches anything": {
			matcher: orMatcher{},
			method:  "GET",
			scheme:  "foo",
			matches: true,
		},
		"matches": {
			matcher: orMatcher{methodMatcher{"GET"}, schemeMatcher("https")},
			method:  "POST",
			scheme:  "https",
			matches: true,
		},
		"does not match": {
			matcher: orMatcher{methodMatcher{"POST"}},
			method:  "GET",
			scheme:  "https",
			matches: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
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
