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

package patternmatcher

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDelimiterIndices(t *testing.T) {
	t.Parallel()

	for tn, tc := range []struct {
		input string
		out   []int
		err   error
	}{
		{input: "<", err: ErrUnbalancedPattern},
		{input: ">", err: ErrUnbalancedPattern},
		{input: ">>", err: ErrUnbalancedPattern},
		{input: "><>", err: ErrUnbalancedPattern},
		{input: "foo.bar<var", err: ErrUnbalancedPattern},
		{input: "foo.bar>var", err: ErrUnbalancedPattern},
		{input: "foo.bar><var", err: ErrUnbalancedPattern},
		{input: "foo.bar<<>var", err: ErrUnbalancedPattern},
		{input: "foo.bar<<>>", out: []int{7, 11}},
		{input: "foo.bar<<>><>", out: []int{7, 11, 11, 13}},
		{input: "foo.bar<<>><>tt<>", out: []int{7, 11, 11, 13, 15, 17}},
	} {
		t.Run(strconv.Itoa(tn), func(t *testing.T) {
			out, err := delimiterIndices(tc.input, '<', '>')
			assert.Equal(t, tc.out, out)
			assert.Equal(t, tc.err, err)
		})
	}
}

func TestIsMatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc           string
		pattern      string
		matchAgainst string
		shouldMatch  bool
	}{
		{
			uc:           "question mark1",
			pattern:      `urn:foo:<?>`,
			matchAgainst: "urn:foo:user",
			shouldMatch:  false,
		},
		{
			uc:           "question mark2",
			pattern:      `urn:foo:<?>`,
			matchAgainst: "urn:foo:u",
			shouldMatch:  true,
		},
		{
			uc:           "question mark3",
			pattern:      `urn:foo:<?>`,
			matchAgainst: "urn:foo:",
			shouldMatch:  false,
		},
		{
			uc:           "question mark4",
			pattern:      `urn:foo:<?>&&<?>`,
			matchAgainst: "urn:foo:w&&r",
			shouldMatch:  true,
		},
		{
			uc:           "question mark5 - both as a special char and a literal",
			pattern:      `urn:foo:<?>?<?>`,
			matchAgainst: "urn:foo:w&r",
			shouldMatch:  false,
		},
		{
			uc:           "question mark5 - both as a special char and a literal1",
			pattern:      `urn:foo:<?>?<?>`,
			matchAgainst: "urn:foo:w?r",
			shouldMatch:  true,
		},
		{
			uc:           "asterisk",
			pattern:      `urn:foo:<*>`,
			matchAgainst: "urn:foo:user",
			shouldMatch:  true,
		},
		{
			uc:           "asterisk1",
			pattern:      `urn:foo:<*>`,
			matchAgainst: "urn:foo:",
			shouldMatch:  true,
		},
		{
			uc:           "asterisk2",
			pattern:      `urn:foo:<*>:<*>`,
			matchAgainst: "urn:foo:usr:swen",
			shouldMatch:  true,
		},
		{
			uc:           "asterisk: both as a special char and a literal",
			pattern:      `*:foo:<*>:<*>`,
			matchAgainst: "urn:foo:usr:swen",
			shouldMatch:  false,
		},
		{
			uc:           "asterisk: both as a special char and a literal1",
			pattern:      `*:foo:<*>:<*>`,
			matchAgainst: "*:foo:usr:swen",
			shouldMatch:  true,
		},
		{
			uc:           "asterisk + question mark",
			pattern:      `urn:foo:<*>:role:<?>`,
			matchAgainst: "urn:foo:usr:role:a",
			shouldMatch:  true,
		},
		{
			uc:           "asterisk + question mark1",
			pattern:      `urn:foo:<*>:role:<?>`,
			matchAgainst: "urn:foo:usr:role:admin",
			shouldMatch:  false,
		},
		{
			uc:           "square brackets",
			pattern:      `urn:foo:<m[a,o,u]n>`,
			matchAgainst: "urn:foo:moon",
			shouldMatch:  false,
		},
		{
			uc:           "square brackets1",
			pattern:      `urn:foo:<m[a,o,u]n>`,
			matchAgainst: "urn:foo:man",
			shouldMatch:  true,
		},
		{
			uc:           "square brackets2",
			pattern:      `urn:foo:<m[!a,o,u]n>`,
			matchAgainst: "urn:foo:man",
			shouldMatch:  false,
		},
		{
			uc:           "square brackets3",
			pattern:      `urn:foo:<m[!a,o,u]n>`,
			matchAgainst: "urn:foo:min",
			shouldMatch:  true,
		},
		{
			uc:           "asterisk matches only one path segment",
			pattern:      `http://example.com/<*>`,
			matchAgainst: "http://example.com/foo/bar",
			shouldMatch:  false,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			matcher, err := newGlobMatcher(tc.pattern)
			require.NoError(t, err)

			// WHEN
			matched := matcher.Match(tc.matchAgainst)

			// THEN
			assert.Equal(t, tc.shouldMatch, matched)
		})
	}
}
