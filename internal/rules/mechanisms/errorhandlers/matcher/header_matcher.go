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

package matcher

import (
	"net/http"
	"strings"
)

type HeaderMatcher map[string][]string

func (hm HeaderMatcher) Match(headers map[string]string) bool {
	for name, patterns := range hm {
		key := http.CanonicalHeaderKey(name)
		if value, found := headers[key]; found && hm.matchesAnyPattern(value, patterns) {
			return true
		}
	}

	return false
}

func (hm HeaderMatcher) matchesAnyPattern(value string, patterns []string) bool {
	for _, headerValue := range hm.headerValuesFrom(value) {
		for _, pattern := range patterns {
			if headerValue.match(pattern) {
				return true
			}
		}
	}

	return false
}

func (hm HeaderMatcher) headerValuesFrom(received string) []*headerValue {
	values := strings.Split(strings.ToLower(received), ",")
	headerValues := make([]*headerValue, len(values))

	for idx, value := range values {
		headerValues[idx] = newHeaderValue(strings.TrimSpace(value))
	}

	return headerValues
}

type headerValue struct {
	Type    string
	Subtype string
}

func newHeaderValue(val string) *headerValue {
	if paramsIdx := strings.IndexRune(val, ';'); paramsIdx != -1 {
		val = val[:paramsIdx]
	}

	typeSubtype := strings.Split(val, "/")
	mediaType := typeSubtype[0]
	mediaSubtype := ""

	if len(typeSubtype) > 1 {
		mediaSubtype = typeSubtype[1]
	}

	return &headerValue{
		Type:    mediaType,
		Subtype: mediaSubtype,
	}
}

func (h *headerValue) match(pattern string) bool {
	if pattern == "*" {
		return true
	}

	pattern = strings.ToLower(pattern)
	typeSubtype := strings.Split(pattern, "/")

	typeMatched := typeSubtype[0] == "*" || h.Type == typeSubtype[0]

	subtypeMatched := (len(h.Subtype) == 0 && len(typeSubtype) == 1) ||
		(len(h.Subtype) != 0 && len(typeSubtype) != 1 && (typeSubtype[1] == "*" || h.Subtype == typeSubtype[1]))

	return typeMatched && subtypeMatched
}
