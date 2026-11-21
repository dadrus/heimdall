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
	pathpkg "path"
	"strings"
)

const pathUpperHex = "0123456789ABCDEF"

// PathInspection describes encoded dot segments and slashes in a path.
type PathInspection struct {
	HasEncodedDotSegments bool
	HasEncodedSlash       bool
}

// InspectPath reports encoded dot segments and slashes in an escaped URL path.
// A dot segment consists of one or two dots bounded by slashes or backslashes,
// including their percent-encoded forms. HasEncodedDotSegments is set when a
// dot or boundary is encoded, or a boundary is a literal backslash. Literal
// dot segments bounded only by slashes are not reported. HasEncodedSlash
// reports any %2F, independently of the dot segments. Escapes are matched
// case-insensitively; malformed triplets count as ordinary characters.
//
//nolint:gocognit,gocyclo,cyclop,funlen
func InspectPath(path string) PathInspection {
	// Ordinary paths have neither escapes nor backslashes.
	idx := strings.IndexByte(path, '%')
	if backslash := strings.IndexByte(path, '\\'); backslash != -1 && (idx == -1 || backslash < idx) {
		idx = backslash
	}

	if idx == -1 {
		return PathInspection{}
	}

	// Recover the literal prefix of the segment containing the first
	// percent sign or backslash, without creating a substring.
	var segmentLen, dotCount int
	for i := idx - 1; i >= 0 && path[i] != '/'; i-- {
		segmentLen++
		if path[i] == '.' {
			dotCount++
		}
	}

	var inspection PathInspection
	var encodedDot, alternativeStart bool

	for i := idx; i < len(path); i++ {
		alternativeEnd := false

		switch path[i] {
		case '/':
		case '\\':
			alternativeEnd = true
		case '.':
			segmentLen++
			dotCount++

			continue
		case '%':
			if i+2 >= len(path) {
				segmentLen++

				continue
			}

			second := path[i+2] | 0x20 //nolint:mnd
			switch {
			case path[i+1] == '2' && second == 'e':
				segmentLen++
				dotCount++
				encodedDot = true
				i += 2

				continue
			case path[i+1] == '2' && second == 'f':
				inspection.HasEncodedSlash = true
				alternativeEnd = true
				i += 2
			case path[i+1] == '5' && second == 'c':
				alternativeEnd = true
				i += 2
			default:
				segmentLen++

				continue
			}
		default:
			segmentLen++

			continue
		}

		if segmentLen == dotCount && (segmentLen == 1 || segmentLen == 2) &&
			(encodedDot || alternativeStart || alternativeEnd) {
			inspection.HasEncodedDotSegments = true
		}

		if inspection.HasEncodedDotSegments && inspection.HasEncodedSlash {
			return inspection
		}

		segmentLen, dotCount = 0, 0
		encodedDot, alternativeStart = false, alternativeEnd
	}

	if segmentLen == dotCount && (segmentLen == 1 || segmentLen == 2) &&
		(encodedDot || alternativeStart) {
		inspection.HasEncodedDotSegments = true
	}

	return inspection
}

func NormalizePath(path string) string {
	if path == "/" {
		return path
	}

	hasTrailingSlash := strings.HasSuffix(path, "/")
	path = pathpkg.Clean(path)

	if hasTrailingSlash && path != "/" {
		path += "/"
	}

	return path
}

// isUnreserved reports whether ch is an RFC 3986 unreserved character.
// See also https://datatracker.ietf.org/doc/html/rfc3986#section-2.3.
//
// UnescapeUnreserved depends on this set excluding '%'. Rule lookup decodes with
// that mode, and captures are decoded again later with UnescapeAllExceptSlash or
// UnescapeAll. Since decoding an unreserved octet can never yield a '%', the first
// pass cannot manufacture a percent-sequence for the second one to consume. Adding
// '%' here would make that double decode observable.
func isUnreserved(ch byte) bool {
	return ch >= 'a' && ch <= 'z' ||
		ch >= 'A' && ch <= 'Z' ||
		ch >= '0' && ch <= '9' ||
		ch == '-' ||
		ch == '.' ||
		ch == '_' ||
		ch == '~'
}

func hexValue(ch byte) byte {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0'
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10 //nolint:mnd
	case ch >= 'A' && ch <= 'F':
		return ch - 'A' + 10 //nolint:mnd
	default:
		return 0xFF //nolint:mnd
	}
}

type UnescapeMode uint8

const (
	UnescapeAll UnescapeMode = iota
	UnescapeAllExceptSlash
	UnescapeUnreserved
)

type UnescapeOptions struct {
	Mode UnescapeMode
}

func (opts UnescapeOptions) shouldUnescape(ch byte) bool {
	switch opts.Mode {
	case UnescapeUnreserved:
		return isUnreserved(ch)
	case UnescapeAllExceptSlash:
		return ch != '/'
	case UnescapeAll:
		return true
	default:
		return false
	}
}

// PathUnescape decodes percent-encoded octets according to opts.
// Malformed percent-encoded sequences are preserved unchanged.
// Decoding is performed in a single pass.
func PathUnescape(value string, opts UnescapeOptions) string {
	start := strings.IndexByte(value, '%')
	if start == -1 {
		return value
	}

	var (
		builder strings.Builder
		last    int
		changed bool
	)

	for idx := start; idx+2 < len(value); idx++ {
		if value[idx] != '%' {
			continue
		}

		high := hexValue(value[idx+1])
		low := hexValue(value[idx+2])
		if high == 0xFF || low == 0xFF { //nolint:mnd
			continue
		}

		decoded := high<<4 | low //nolint:mnd
		if !opts.shouldUnescape(decoded) {
			idx += 2

			continue
		}

		if !changed {
			builder.Grow(len(value))
			changed = true
		}

		builder.WriteString(value[last:idx])
		builder.WriteByte(decoded)

		idx += 2
		last = idx + 1
	}

	if !changed {
		return value
	}

	builder.WriteString(value[last:])

	return builder.String()
}

// EscapedPath returns a valid encoded path while preserving existing
// percent-encoded octets from URL.RawPath.
//
// It assumes that RawPath originates from URL parsing and represents Path.
// Unlike url.URL.EscapedPath, an invalid literal byte in RawPath does not cause
// the complete encoded representation to be discarded.
//
//nolint:cyclop
func EscapedPath(value *url.URL) string {
	if value.RawPath == "" {
		return value.EscapedPath()
	}

	rawPath := value.RawPath
	first := -1

	// Find the first byte to escape
	for idx := 0; idx < len(rawPath); idx++ {
		current := rawPath[idx]

		if current == '%' &&
			idx+2 < len(rawPath) &&
			isHexDigit(rawPath[idx+1]) &&
			isHexDigit(rawPath[idx+2]) {
			idx += 2

			continue
		}

		if !isValidEncodedPathByte(current) {
			first = idx

			break
		}
	}

	if first == -1 {
		return rawPath
	}

	escapeCount := 1

	// Count the remaining bytes requiring escaping so that the builder can
	// allocate the exact output capacity.
	for idx := first + 1; idx < len(rawPath); idx++ {
		current := rawPath[idx]

		if current == '%' &&
			idx+2 < len(rawPath) &&
			isHexDigit(rawPath[idx+1]) &&
			isHexDigit(rawPath[idx+2]) {
			idx += 2

			continue
		}

		if !isValidEncodedPathByte(current) {
			escapeCount++
		}
	}

	var result strings.Builder

	// Every escaped byte replaces one byte with three bytes.
	result.Grow(len(rawPath) + 2*escapeCount)
	result.WriteString(rawPath[:first])

	for idx := first; idx < len(rawPath); idx++ {
		current := rawPath[idx]

		if current == '%' &&
			idx+2 < len(rawPath) &&
			isHexDigit(rawPath[idx+1]) &&
			isHexDigit(rawPath[idx+2]) {
			result.WriteString(rawPath[idx : idx+3])
			idx += 2

			continue
		}

		if isValidEncodedPathByte(current) {
			result.WriteByte(current)

			continue
		}

		result.WriteByte('%')
		result.WriteByte(pathUpperHex[current>>4])
		result.WriteByte(pathUpperHex[current&0x0f])
	}

	return result.String()
}

func isHexDigit(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}

// Mirrors the characters accepted by net/url for an encoded path.
// In particular, '?' and '#' are not valid literal path bytes here.
func isValidEncodedPathByte(value byte) bool {
	if value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' {
		return true
	}

	switch value {
	case '-', '_', '.', '~',
		'/',
		'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=',
		':', '@', '[', ']':
		return true

	default:
		return false
	}
}
