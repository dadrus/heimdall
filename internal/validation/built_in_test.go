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

package validation

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMutableUpstreamHeaderValidatorTag(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "mutable_upstream_header", mutableUpstreamHeaderValidator{}.Tag())
}

func TestMutableUpstreamHeaderValidatorValidate(t *testing.T) {
	t.Parallel()

	validator := mutableUpstreamHeaderValidator{}

	for uc, tc := range map[string]struct {
		value    any
		expected bool
	}{
		"empty header is accepted by policy validator": {
			value:    "",
			expected: true,
		},
		"Authorization is accepted": {
			value:    "Authorization",
			expected: true,
		},
		"Host is accepted": {
			value:    "Host",
			expected: true,
		},
		"custom header is accepted": {
			value:    "X-Custom",
			expected: true,
		},
		"Forwarded is rejected": {
			value:    "Forwarded",
			expected: false,
		},
		"X-Forwarded header is rejected": {
			value:    "X-Forwarded-For",
			expected: false,
		},
		"arbitrary X-Forwarded header is rejected": {
			value:    "X-Forwarded-Prefix",
			expected: false,
		},
		"proxy-owned validation is case-insensitive": {
			value:    "x-fOrWaRdEd-CuStOm",
			expected: false,
		},
		"Connection is rejected": {
			value:    "Connection",
			expected: false,
		},
		"Content-Length is rejected": {
			value:    "Content-Length",
			expected: false,
		},
		"transport validation is case-insensitive": {
			value:    "tRaNsFeR-EnCoDiNg",
			expected: false,
		},
		"non-string value is rejected": {
			value:    42,
			expected: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, validator.Validate("", reflect.ValueOf(tc.value)))
		})
	}
}

func TestMutableUpstreamHeaderValidatorAlwaysValidate(t *testing.T) {
	t.Parallel()

	assert.False(t, mutableUpstreamHeaderValidator{}.AlwaysValidate())
}

func TestMutableUpstreamHeaderValidatorMessageTemplate(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "{0} {1}", mutableUpstreamHeaderValidator{}.MessageTemplate())
}

func TestMutableUpstreamHeaderValidatorErrorMessage(t *testing.T) {
	t.Parallel()

	assert.Equal(
		t,
		"is not a mutable upstream header",
		mutableUpstreamHeaderValidator{}.ErrorMessage(""),
	)
}
