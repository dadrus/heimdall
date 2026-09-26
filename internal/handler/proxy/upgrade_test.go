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

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUpgradeRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		headers  http.Header
		expected bool
	}{
		"upgrade connection option and upgrade header are present": {
			headers: http.Header{
				"Connection": []string{"keep-alive, Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
			expected: true,
		},
		"upgrade connection option is present multiple times": {
			headers: http.Header{
				"Connection": []string{"keep-alive", "upgrade"},
				"Upgrade":    []string{"websocket"},
			},
			expected: true,
		},
		"upgrade header is missing": {
			headers: http.Header{
				"Connection": []string{"Upgrade"},
			},
			expected: false,
		},
		"upgrade connection option is missing": {
			headers: http.Header{
				"Connection": []string{"keep-alive"},
				"Upgrade":    []string{"websocket"},
			},
			expected: false,
		},
		"connection header is missing": {
			headers: http.Header{
				"Upgrade": []string{"websocket"},
			},
			expected: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://foo.bar/test", nil)
			req.Header = tc.headers

			// WHEN
			actual := isUpgradeRequest(req)

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}
