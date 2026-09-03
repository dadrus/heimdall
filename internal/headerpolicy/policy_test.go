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

package headerpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		name     string
		expected Class
	}{
		"Authorization is ordinary": {
			name:     "Authorization",
			expected: Ordinary,
		},
		"Content-Digest is ordinary": {
			name:     "Content-Digest",
			expected: Ordinary,
		},
		"Signature is ordinary": {
			name:     "Signature",
			expected: Ordinary,
		},
		"Signature-Input is ordinary": {
			name:     "Signature-Input",
			expected: Ordinary,
		},
		"Host is ordinary": {
			name:     "Host",
			expected: Ordinary,
		},
		"custom header is ordinary": {
			name:     "X-Custom",
			expected: Ordinary,
		},
		"X-Forwarded without suffix is ordinary": {
			name:     "X-Forwarded",
			expected: Ordinary,
		},
		"Forwarded is proxy-owned": {
			name:     "Forwarded",
			expected: ProxyOwned,
		},
		"known X-Forwarded header is proxy-owned": {
			name:     "X-Forwarded-For",
			expected: ProxyOwned,
		},
		"arbitrary X-Forwarded header is proxy-owned": {
			name:     "X-Forwarded-Prefix",
			expected: ProxyOwned,
		},
		"proxy-owned classification is case-insensitive": {
			name:     "x-fOrWaRdEd-CuStOm",
			expected: ProxyOwned,
		},
		"Connection is transport-managed": {
			name:     "Connection",
			expected: Transport,
		},
		"Proxy-Connection is transport-managed": {
			name:     "Proxy-Connection",
			expected: Transport,
		},
		"Keep-Alive is transport-managed": {
			name:     "Keep-Alive",
			expected: Transport,
		},
		"Proxy-Authenticate is transport-managed": {
			name:     "Proxy-Authenticate",
			expected: Transport,
		},
		"Proxy-Authorization is transport-managed": {
			name:     "Proxy-Authorization",
			expected: Transport,
		},
		"TE is transport-managed": {
			name:     "TE",
			expected: Transport,
		},
		"Trailer is transport-managed": {
			name:     "Trailer",
			expected: Transport,
		},
		"Transfer-Encoding is transport-managed": {
			name:     "Transfer-Encoding",
			expected: Transport,
		},
		"Upgrade is transport-managed": {
			name:     "Upgrade",
			expected: Transport,
		},
		"Content-Length is transport-managed": {
			name:     "Content-Length",
			expected: Transport,
		},
		"transport classification is case-insensitive": {
			name:     "tRaNsFeR-EnCoDiNg",
			expected: Transport,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, Classify(tc.name))
		})
	}
}

func TestShouldSanitizeInput(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		name     string
		expected bool
	}{
		"ordinary header is not sanitized": {
			name:     "Authorization",
			expected: false,
		},
		"Host is not sanitized": {
			name:     "Host",
			expected: false,
		},
		"Forwarded is preserved for preparation": {
			name:     "Forwarded",
			expected: false,
		},
		"X-Forwarded-For is preserved for preparation": {
			name:     "X-Forwarded-For",
			expected: false,
		},
		"X-Forwarded-Host is preserved for preparation": {
			name:     "X-Forwarded-Host",
			expected: false,
		},
		"X-Forwarded-Proto is preserved for preparation": {
			name:     "X-Forwarded-Proto",
			expected: false,
		},
		"X-Forwarded-Method is sanitized": {
			name:     "X-Forwarded-Method",
			expected: true,
		},
		"X-Forwarded-Uri is sanitized": {
			name:     "X-Forwarded-Uri",
			expected: true,
		},
		"X-Forwarded-Path is sanitized": {
			name:     "X-Forwarded-Path",
			expected: true,
		},
		"arbitrary X-Forwarded header is protected but not sanitized": {
			name:     "X-Forwarded-Custom",
			expected: false,
		},
		"Connection is sanitized": {
			name:     "Connection",
			expected: true,
		},
		"Keep-Alive is sanitized": {
			name:     "Keep-Alive",
			expected: true,
		},
		"TE is sanitized": {
			name:     "TE",
			expected: true,
		},
		"Transfer-Encoding is sanitized": {
			name:     "Transfer-Encoding",
			expected: true,
		},
		"Content-Length is protected but not sanitized here": {
			name:     "Content-Length",
			expected: false,
		},
		"sanitization is case-insensitive": {
			name:     "x-fOrWaRdEd-MeThOd",
			expected: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, ShouldSanitizeInput(tc.name))
		})
	}
}
