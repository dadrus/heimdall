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
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// These deliberately simple reference implementations do not use the URL/path
// helpers under test. They model their documented contracts rather than their
// scanning and builder algorithms. Performance is not a concern for test code.

type referencePathToken struct {
	value   byte
	encoded bool
}

func referencePathTokens(path string) []referencePathToken {
	tokens := make([]referencePathToken, 0, len(path))

	for i := 0; i < len(path); {
		if path[i] == '%' && i+2 < len(path) {
			if decoded, err := hex.DecodeString(path[i+1 : i+3]); err == nil {
				tokens = append(tokens, referencePathToken{value: decoded[0], encoded: true})
				i += 3

				continue
			}
		}

		tokens = append(tokens, referencePathToken{value: path[i]})
		i++
	}

	return tokens
}

func referenceInspectPath(path string) PathInspection {
	tokens := referencePathTokens(path)

	var result PathInspection
	for _, token := range tokens {
		if token.encoded && token.value == '/' {
			result.HasEncodedSlash = true
		}
	}

	// Split at literal and encoded slashes/backslashes, preserving the origin
	// of each boundary. Only one- or two-dot segments are significant.
	start := 0
	leftAlternative := false

	for i, token := range tokens {
		if token.value != '/' && token.value != '\\' {
			continue
		}

		rightAlternative := token.encoded || token.value == '\\'
		if referenceIsEncodedDotSegment(tokens[start:i], leftAlternative || rightAlternative) {
			result.HasEncodedDotSegments = true
		}

		start = i + 1
		leftAlternative = rightAlternative
	}

	if referenceIsEncodedDotSegment(tokens[start:], leftAlternative) {
		result.HasEncodedDotSegments = true
	}

	return result
}

func referenceIsEncodedDotSegment(segment []referencePathToken, alternativeBoundary bool) bool {
	if len(segment) != 1 && len(segment) != 2 {
		return false
	}

	encodedDot := false
	for _, token := range segment {
		if token.value != '.' {
			return false
		}

		encodedDot = encodedDot || token.encoded
	}

	return encodedDot || alternativeBoundary
}

func referencePathUnescape(value string, mode UnescapeMode) string {
	var result strings.Builder
	result.Grow(len(value))

	for i := 0; i < len(value); {
		if value[i] == '%' && i+2 < len(value) {
			if decoded, err := hex.DecodeString(value[i+1 : i+3]); err == nil {
				octet := decoded[0]
				if referenceShouldUnescape(octet, mode) {
					result.WriteByte(octet)
				} else {
					result.WriteString(value[i : i+3])
				}

				i += 3

				continue
			}
		}

		result.WriteByte(value[i])
		i++
	}

	return result.String()
}

func referenceShouldUnescape(octet byte, mode UnescapeMode) bool {
	switch mode {
	case UnescapeAll:
		return true
	case UnescapeAllExceptSlash:
		return octet != '/'
	case UnescapeUnreserved:
		return octet >= 'a' && octet <= 'z' ||
			octet >= 'A' && octet <= 'Z' ||
			octet >= '0' && octet <= '9' ||
			strings.IndexByte("-._~", octet) >= 0
	default:
		return false
	}
}

// The allowed literal bytes reflect the URL path alphabet accepted by net/url,
// including square brackets. All other bytes, including malformed '%' escapes,
// must be escaped; existing valid triplets must retain their exact spelling.
const referenceRawPathLiterals = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/!$&'()*+,;=:@[]"

func referenceRepairEscapedPath(rawPath string) string {
	var result strings.Builder

	for i := 0; i < len(rawPath); {
		if rawPath[i] == '%' && i+2 < len(rawPath) {
			if _, err := hex.DecodeString(rawPath[i+1 : i+3]); err == nil {
				result.WriteString(rawPath[i : i+3])
				i += 3

				continue
			}
		}

		if strings.IndexByte(referenceRawPathLiterals, rawPath[i]) >= 0 {
			result.WriteByte(rawPath[i])
		} else {
			fmt.Fprintf(&result, "%%%02X", rawPath[i])
		}

		i++
	}

	return result.String()
}

// Case changes in valid escape triplets cannot alter their decoded octet.
// Unrecognized sequences are deliberately left unchanged.
func flipEscapeHexCase(value string) string {
	result := []byte(value)

	for i := 0; i+2 < len(result); i++ {
		if result[i] != '%' {
			continue
		}

		if _, err := hex.DecodeString(string(result[i+1 : i+3])); err != nil {
			continue
		}

		for j := i + 1; j < i+3; j++ {
			switch {
			case result[j] >= 'a' && result[j] <= 'f':
				result[j] -= 'a' - 'A'
			case result[j] >= 'A' && result[j] <= 'F':
				result[j] += 'a' - 'A'
			}
		}

		i += 2
	}

	return string(result)
}

// Encode a literal alphanumeric byte, never a byte inside an existing escape.
// It remains a non-dot, non-separator token after the transformation.
func encodeHarmlessLiteral(value string) string {
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			if _, err := hex.DecodeString(value[i+1 : i+3]); err == nil {
				i += 2

				continue
			}
		}

		ch := value[i]
		if ch >= 'a' && ch <= 'z' ||
			ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' {
			return value[:i] + fmt.Sprintf("%%%02X", ch) + value[i+1:]
		}
	}

	return value
}

// Anchor the reference models in explicit examples. The fuzz tests compare
// implementations, but two implementations can otherwise share a bad assumption.
func TestReferenceInspectPath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		path string
		want PathInspection
	}{
		{path: "/a/../b"},
		{path: "/a/./b"},
		{path: "/a/%2E%2e/b", want: PathInspection{HasEncodedDotSegments: true}},
		{path: "/a/.%2E/b", want: PathInspection{HasEncodedDotSegments: true}},
		{path: "/a%2f../b", want: PathInspection{HasEncodedDotSegments: true, HasEncodedSlash: true}},
		{path: "/a%5c../b", want: PathInspection{HasEncodedDotSegments: true}},
		{path: "/a\\../b", want: PathInspection{HasEncodedDotSegments: true}},
		{path: "/api/a%2Fb/../c", want: PathInspection{HasEncodedSlash: true}},
		{path: "/files/name%2Etxt"},
		{path: "/files/%252e%252e"},
		{path: "/%ZZ/%2/%"},
		{path: "/fetch/http%3A%2F%2Fexample.com%2Ffiles%2F..%2Fdocument.pdf", want: PathInspection{HasEncodedDotSegments: true, HasEncodedSlash: true}},
	} {
		require.Equal(t, tc.want, referenceInspectPath(tc.path), "path=%q", tc.path)
	}
}

func TestReferencePathUnescape(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value string
		mode  UnescapeMode
		want  string
	}{
		{value: "%61%2F%25", mode: UnescapeAll, want: "a/%"},
		{value: "%61%2f%25", mode: UnescapeAllExceptSlash, want: "a%2f%"},
		{value: "%61%2F%25", mode: UnescapeUnreserved, want: "a%2F%25"},
		{value: "%ZZ%61%2", mode: UnescapeAll, want: "%ZZa%2"},
		{value: "%2%46", mode: UnescapeAll, want: "%2F"},
		{value: "%252e", mode: UnescapeAll, want: "%2e"},
		{value: "%252e", mode: UnescapeUnreserved, want: "%252e"},
		{value: "%2f", mode: UnescapeMode(255), want: "%2f"},
	} {
		require.Equal(t, tc.want, referencePathUnescape(tc.value, tc.mode), "value=%q, mode=%d", tc.value, tc.mode)
	}
}

func TestReferenceRepairEscapedPath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		rawPath string
		want    string
	}{
		{rawPath: "/api/%61dmin", want: "/api/%61dmin"},
		{rawPath: "/files/a%2fb", want: "/files/a%2fb"},
		{rawPath: "/api/a b|c", want: "/api/a%20b%7Cc"},
		{rawPath: "/api/%ZZ/%2/%", want: "/api/%25ZZ/%252/%25"},
		{rawPath: "/foo[x]?y#z", want: "/foo[x]%3Fy%23z"},
	} {
		require.Equal(t, tc.want, referenceRepairEscapedPath(tc.rawPath), "rawPath=%q", tc.rawPath)
	}
}
