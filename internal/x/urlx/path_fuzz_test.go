// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package urlx

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func FuzzPathUnescape(f *testing.F) {
	allOpts := UnescapeOptions{Mode: UnescapeAll}
	allExceptSlashOpts := UnescapeOptions{Mode: UnescapeAllExceptSlash}
	unreservedOpts := UnescapeOptions{Mode: UnescapeUnreserved}

	for _, value := range []string{
		"",
		"/api/v1/resource",
		"/api/%61dmin",
		"/api/%61%64%6D%69%6E",
		"/api/%2F/resource",
		"/api/%2f/resource",
		"/api/%252F/%2561",
		"/proxy/https%3A%2F%2Fexample.com",
		"/foo%5Bbar%5D",
		"/api/%ZZ/%2/%",
		"%25%36%31",
		"%2%46",
		"%6%31",
		"\x00%00\xff",
	} {
		f.Add(value)
	}

	f.Fuzz(func(t *testing.T, value string) {
		all := PathUnescape(value, allOpts)
		allExceptSlash := PathUnescape(value, allExceptSlashOpts)
		unreserved := PathUnescape(value, unreservedOpts)

		// A decoded triplet is replaced by a single byte. Preserved and
		// malformed sequences retain their original length.
		require.LessOrEqual(t, len(all), len(value))
		require.LessOrEqual(t, len(allExceptSlash), len(value))
		require.LessOrEqual(t, len(unreserved), len(value))

		// An unsupported mode must preserve the input unchanged.
		require.Equal(
			t,
			value,
			PathUnescape(
				value,
				UnescapeOptions{Mode: UnescapeMode(255)},
			),
		)

		// The two broader modes can differ only if the original value
		// contains an encoded slash.
		if !ContainsEncodedSlash(value) {
			require.Equal(t, all, allExceptSlash)
		}

		expected, err := url.PathUnescape(value)
		if err != nil {
			// The remaining invariants assume syntactically valid
			// percent-encoded input. Decoding valid sequences adjacent
			// to malformed ones can form new escape sequences.
			return
		}

		// UnescapeAll must have the same decoding semantics as the
		// standard library for syntactically valid input.
		require.Equal(t, expected, all)

		// Canonicalizing unreserved octets before applying a broader
		// decoding mode must not change the final result.
		require.Equal(
			t,
			all,
			PathUnescape(unreserved, allOpts),
		)
		require.Equal(
			t,
			allExceptSlash,
			PathUnescape(unreserved, allExceptSlashOpts),
		)
	})
}
