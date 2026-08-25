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

package pipeline

import (
	"net/http"
	"strings"
)

// Headers provides a read-only, lazily normalized view on HTTP headers.
//
// The underlying http.Header is neither copied nor modified. It must therefore
// not be mutated for the lifetime of Headers.
//
// Header values are normalized on first access. If multiple values exist for a
// header, they are joined using a comma. The normalized value is cached and
// reused for subsequent accesses using the same header name.
//
// Headers is request-scoped and not safe for concurrent use.
type Headers struct {
	values http.Header
	cache  map[string]string
}

// NewHeaders creates a read-only view on the supplied HTTP headers.
//
// No headers are copied or normalized when this function is called.
func NewHeaders(values http.Header) Headers {
	return Headers{
		values: values,
	}
}

// Get returns the normalized value associated with name.
//
// Header names are matched case-insensitively.
//
// If no value exists, an empty string is returned. A single value is returned
// unchanged. Multiple values are joined using a comma.
//
// The result is cached on first access and reused for subsequent accesses
// using the same header name.
func (h *Headers) Get(name string) string {
	if h == nil {
		return ""
	}

	if value, ok := h.cache[name]; ok {
		return value
	}

	value := strings.Join(h.values.Values(name), ",")

	if h.cache == nil {
		h.cache = make(map[string]string)
	}

	h.cache[name] = value

	return value
}
