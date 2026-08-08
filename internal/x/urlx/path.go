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

//nolint:gocognit,gocyclo,gocyclo,cyclop,funlen
func PathHasDotSegments(path string) bool {
	iDot := strings.IndexByte(path, '.')
	iPct := strings.IndexByte(path, '%')
	iBsl := strings.IndexByte(path, '\\')

	idx := iDot
	if idx == -1 || (iPct != -1 && iPct < idx) {
		idx = iPct
	}

	if idx == -1 || (iBsl != -1 && iBsl < idx) {
		idx = iBsl
	}

	if idx == -1 {
		return false
	}

	segLen := 0
	for i := idx - 1; i >= 0 && path[i] != '/'; i-- {
		segLen++
	}

	dotCount := 0

	for i := idx; i < len(path); {
		switch path[i] {
		case '/', '\\':
			if (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2) {
				return true
			}

			segLen = 0
			dotCount = 0
			i++
		case '.':
			segLen++
			dotCount++
			i++
		case '%':
			if i+2 >= len(path) {
				segLen++
				i++

				continue
			}

			h1 := path[i+1]
			h2 := path[i+2] | 0x20 //nolint:mnd

			switch {
			case h1 == '2' && h2 == 'e':
				segLen++
				dotCount++
				i += 3
			case h1 == '2' && h2 == 'f':
				if (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2) {
					return true
				}

				segLen = 0
				dotCount = 0
				i += 3
			case h1 == '5' && h2 == 'c':
				if (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2) {
					return true
				}

				segLen = 0
				dotCount = 0
				i += 3
			default:
				segLen++
				i++
			}
		default:
			segLen++
			i++
		}
	}

	return (segLen == 1 && dotCount == 1) || (segLen == 2 && dotCount == 2)
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

// ContainsEncodedSlash reports whether path contains a URL-encoded slash
// sequence, case-insensitive, e.g. %2F or %2f.
func ContainsEncodedSlash(path string) bool {
	for i := strings.IndexByte(path, '%'); i != -1; {
		if i+2 < len(path) && path[i+1] == '2' && (path[i+2]|0x20) == 'f' { //nolint:mnd
			return true
		}

		next := strings.IndexByte(path[i+1:], '%')
		if next == -1 {
			break
		}

		i += next + 1
	}

	return false
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
