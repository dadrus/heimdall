// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package validation

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/inhies/go-bytesize"

	"github.com/dadrus/heimdall/internal/headerpolicy"
)

type notAllowedValidator struct{}

func (v notAllowedValidator) Tag() string                  { return "not_allowed" }
func (v notAllowedValidator) AlwaysValidate() bool         { return true }
func (v notAllowedValidator) MessageTemplate() string      { return "{0} {1}" }
func (v notAllowedValidator) ErrorMessage(_ string) string { return "is not allowed" }

func (v notAllowedValidator) Validate(_ string, field reflect.Value) bool {
	switch field.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return field.IsNil()
	default:
		return false
	}
}

type urlValidator struct{}

func (v urlValidator) Tag() string                  { return "url" }
func (v urlValidator) AlwaysValidate() bool         { return false }
func (v urlValidator) MessageTemplate() string      { return "{0} {1}" }
func (v urlValidator) ErrorMessage(_ string) string { return "must be a valid URL" }

//nolint:cyclop
func (v urlValidator) Validate(_ string, field reflect.Value) bool {
	if !field.IsValid() {
		return false
	}

	var raw string

	switch v := field.Interface().(type) {
	case string:
		raw = v
	case fmt.Stringer:
		raw = v.String()
	default:
		return false
	}

	raw = strings.ToLower(raw)

	if len(raw) == 0 {
		return false
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return false
	}

	isFileScheme := parsed.Scheme == "file"

	if (isFileScheme && (len(parsed.Path) == 0 || parsed.Path == "/")) ||
		(!isFileScheme && len(parsed.Host) == 0 && len(parsed.Fragment) == 0 && len(parsed.Opaque) == 0) {
		return false
	}

	return true
}

type mutableUpstreamHeaderValidator struct{}

func (mutableUpstreamHeaderValidator) Tag() string             { return "mutable_upstream_header" }
func (mutableUpstreamHeaderValidator) AlwaysValidate() bool    { return false }
func (mutableUpstreamHeaderValidator) MessageTemplate() string { return "{0} {1}" }

func (mutableUpstreamHeaderValidator) ErrorMessage(_ string) string {
	return "is not a mutable upstream header"
}

func (mutableUpstreamHeaderValidator) Validate(_ string, field reflect.Value) bool {
	if field.Kind() != reflect.String {
		return false
	}

	return headerpolicy.Classify(field.String()) == headerpolicy.Ordinary
}

type maxBytes struct{}

func (maxBytes) Validate(param string, field reflect.Value) bool {
	size, ok := field.Interface().(bytesize.ByteSize)
	if !ok {
		return false
	}

	maxSize, err := bytesize.Parse(param)
	if err != nil {
		return false
	}

	return size <= maxSize
}

func (maxBytes) Tag() string                      { return "max_bytes" }
func (maxBytes) AlwaysValidate() bool             { return false }
func (maxBytes) MessageTemplate() string          { return "{0} {1}" }
func (maxBytes) ErrorMessage(param string) string { return "must not exceed " + param }
