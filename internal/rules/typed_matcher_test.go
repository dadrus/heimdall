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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegexPatternMatcher(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		expression string
		matches    string
		assert     func(t *testing.T, err error, matched bool)
	}{
		"with empty expression": {
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoRegexPatternDefined)
			},
		},
		"with bad regex expression": {
			expression: "?>?<*??",
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "error parsing regexp")
			},
		},
		"doesn't match": {
			expression: "^/foo/(bar|baz)/zab",
			matches:    "/foo/zab/zab",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, matched)
			},
		},
		"successful": {
			expression: "^/foo/(bar|baz)/zab",
			matches:    "/foo/bar/zab",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, matched)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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

	for uc, tc := range map[string]struct {
		expression string
		matches    string
		assert     func(t *testing.T, err error, matched bool)
	}{
		"with empty expression": {
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoGlobPatternDefined)
			},
		},
		"with bad glob expression": {
			expression: "!*][)(*",
			assert: func(t *testing.T, err error, _ bool) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "unexpected end of input")
			},
		},
		"doesn't match": {
			expression: "{/**.foo,/**.bar}",
			matches:    "/foo.baz",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, matched)
			},
		},
		"successful": {
			expression: "{/**.foo,/**.bar}",
			matches:    "/foo.bar",
			assert: func(t *testing.T, err error, matched bool) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, matched)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			var matched bool

			matcher, err := newGlobMatcher(tc.expression, '/')
			if matcher != nil {
				matched = matcher.match(tc.matches)
			}

			tc.assert(t, err, matched)
		})
	}
}

func TestExactMatcher(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		expression string
		toMatch    string
		matches    bool
	}{
		"matches":       {"foo", "foo", true},
		"doesn't match": {"foo", "bar", false},
	} {
		t.Run(uc, func(t *testing.T) {
			matcher := newExactMatcher(tc.expression)

			matches := matcher.match(tc.toMatch)
			assert.Equal(t, tc.matches, matches)
		})
	}
}
