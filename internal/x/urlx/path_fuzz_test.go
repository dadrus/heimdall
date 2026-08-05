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

func FuzzEscapedPath(f *testing.F) {
	for _, seed := range []struct {
		path    string
		rawPath string
	}{
		{path: ""},
		{path: "."},
		{path: ".."},
		{path: "/api/v1/resource"},
		{path: "/api/a b|c"},
		{rawPath: "/api/v1/resource"},
		{rawPath: "/api/%61dmin"},
		{rawPath: "/admin/%2e%2e%2fpublic/x|"},
		{rawPath: "/files/a%2Fb|"},
		{rawPath: "/proxy/https%3A%2F%2Fexample.com|"},
		{rawPath: "/api/%ZZ/%2/%"},
		{rawPath: "%25%36%31"},
		{rawPath: "\x00%00\xff"},
	} {
		f.Add(seed.path, seed.rawPath)
	}

	f.Fuzz(func(t *testing.T, path, rawPath string) {
		if rawPath != "" {
			// Build a consistent URL value even for RawPath strings that the
			// standard library considers malformed. EscapedPath repairs those
			// literal bytes while preserving all valid encoded octets.
			path = PathUnescape(rawPath, UnescapeOptions{Mode: UnescapeAll})
		}

		value := &url.URL{Path: path, RawPath: rawPath}
		result := EscapedPath(value)

		// Without RawPath the helper must have exactly the standard-library
		// semantics.
		if rawPath == "" {
			require.Equal(t, value.EscapedPath(), result)
		}

		// A RawPath already accepted by net/url must be returned byte-for-byte.
		if rawPath != "" && value.EscapedPath() == rawPath {
			require.Equal(t, rawPath, result)
		}

		// Repairing RawPath can only preserve or expand it: every invalid
		// literal byte is replaced by one three-byte percent sequence. When
		// RawPath is absent, result is derived from Path instead.
		if rawPath != "" {
			require.GreaterOrEqual(t, len(result), len(rawPath))
		}

		decoded, err := url.PathUnescape(result)
		require.NoError(t, err)
		require.Equal(t, path, decoded)

		// The returned value must be a RawPath net/url accepts, and processing it
		// again must be idempotent.
		canonical := &url.URL{Path: path, RawPath: result}
		require.Equal(t, result, canonical.EscapedPath())
		require.Equal(t, result, EscapedPath(canonical))

		// When RawPath is present, repairing it must preserve the
		// security-relevant encoded-slash and dot-segment semantics. Without
		// RawPath there is no encoded source representation to compare against;
		// the helper delegates to net/url, which is asserted above.
		if rawPath != "" {
			require.Equal(t, ContainsEncodedSlash(rawPath), ContainsEncodedSlash(result))
			require.Equal(t, PathHasDotSegments(rawPath), PathHasDotSegments(result))
		}

		// Existing percent-encoded octets must never disappear or have their hex
		// casing rewritten. The repair path may add new uppercase octets.
		before := countEncodedOctets(rawPath)
		after := countEncodedOctets(result)
		for octet, count := range before {
			require.GreaterOrEqual(t, after[octet], count, "octet", octet)
		}

		// Literal slash and dot bytes are valid path bytes, so repairing cannot
		// create additional encoded slash or dot octets. Exact counts here guard
		// the encodings used by both path-security checks.
		for _, octet := range []string{"%2F", "%2f", "%2E", "%2e"} {
			require.Equal(t, before[octet], after[octet], "octet", octet)
		}
	})
}

func countEncodedOctets(value string) map[string]int {
	result := make(map[string]int)

	for idx := 0; idx+2 < len(value); idx++ {
		if value[idx] != '%' ||
			!isHexDigit(value[idx+1]) ||
			!isHexDigit(value[idx+2]) {
			continue
		}

		result[value[idx:idx+3]]++
		idx += 2
	}

	return result
}

