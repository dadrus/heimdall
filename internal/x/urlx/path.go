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

// Unescape decodes URL-escaped path value.
// If decodeEncodedSlash is false, encoded slashes (%2F / %2f) are preserved.
func Unescape(value string, decodeEncodedSlash bool) string { //nolint:cyclop
	start := strings.IndexByte(value, '%')
	if start == -1 {
		return value
	}

	if decodeEncodedSlash {
		unescaped, _ := url.PathUnescape(value)

		return unescaped
	}

	var builder strings.Builder
	builder.Grow(len(value))
	builder.WriteString(value[:start])

	for i := start; i < len(value); {
		j := i
		for j < len(value) && value[j] != '%' {
			j++
		}

		if j > i {
			builder.WriteString(value[i:j])
			i = j
		}

		if i >= len(value) {
			break
		}

		if i+2 >= len(value) {
			builder.WriteByte(value[i])
			i++

			continue
		}

		hi := hexValue(value[i+1])
		lo := hexValue(value[i+2])

		if hi == 0xFF || lo == 0xFF { //nolint:mnd
			builder.WriteByte(value[i])
			i++

			continue
		}

		decoded := (hi << 4) | lo //nolint:mnd
		if decoded == '/' {
			builder.WriteByte(value[i])
			builder.WriteByte(value[i+1])
			builder.WriteByte(value[i+2])
			i += 3

			continue
		}

		builder.WriteByte(decoded)

		i += 3
	}

	return builder.String()
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
