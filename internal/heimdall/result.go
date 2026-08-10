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

package heimdall

import (
	"encoding/json"
	"net/http"
)

// Results contains the results produced by executed pipeline steps.
type Results map[string]*Result

// Result represents the result produced by a pipeline step.
//
// Payload is directly available to templates and CEL expressions.
//
// Response headers are intentionally not exposed as a mutable collection.
// They can only be accessed through Header.
type Result struct {
	Payload any

	headers    Headers
	hasHeaders bool
}

// NewResult creates a result containing a payload.
func NewResult(payload any) *Result {
	return &Result{
		Payload: payload,
	}
}

// NewResultWithHeaders creates a result containing a payload and HTTP response
// headers.
//
// The supplied headers are not copied or modified. They must therefore not be
// mutated for the lifetime of the result.
func NewResultWithHeaders(payload any, headers http.Header) *Result {
	return &Result{
		Payload:    payload,
		headers:    NewHeaders(headers),
		hasHeaders: true,
	}
}

// Header returns the value associated with the given header name.
//
// Its semantics intentionally match Request.Header:
//
//   - a missing header results in an empty string;
//   - a single value is returned as-is;
//   - multiple values are returned as a comma-separated string.
//
// Header values are normalized lazily and cached by Headers.
func (r *Result) Header(name string) string {
	if r == nil || !r.hasHeaders {
		return ""
	}

	return r.headers.Get(name)
}

func (r *Result) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}

	if !r.hasHeaders {
		return json.Marshal(struct {
			Payload any `json:"payload"`
		}{
			Payload: r.Payload,
		})
	}

	return json.Marshal(struct {
		Headers http.Header `json:"headers"`
		Payload any         `json:"payload"`
	}{
		Headers: r.headers.values,
		Payload: r.Payload,
	})
}

func (r *Result) UnmarshalJSON(data []byte) error {
	var value struct {
		Headers json.RawMessage `json:"headers"`
		Payload any             `json:"payload"`
	}

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	r.Payload = value.Payload
	r.headers = Headers{}
	r.hasHeaders = false

	if value.Headers == nil {
		return nil
	}

	var headers http.Header

	if err := json.Unmarshal(value.Headers, &headers); err != nil {
		return err
	}

	r.headers = NewHeaders(headers)
	r.hasHeaders = true

	return nil
}
