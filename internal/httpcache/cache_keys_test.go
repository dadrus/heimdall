// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package httpcache

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestTargetIDPartitionsByAuthorization(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		firstAuthorization  string
		secondAuthorization string
		expectedEqual       bool
	}{
		"should produce the same target id for equal authorization": {
			firstAuthorization:  "Bearer alice",
			secondAuthorization: "Bearer alice",
			expectedEqual:       true,
		},
		"should normalize surrounding authorization whitespace": {
			firstAuthorization:  "  Bearer alice  ",
			secondAuthorization: "Bearer alice",
			expectedEqual:       true,
		},
		"should treat blank authorization as absent": {
			firstAuthorization:  "   ",
			secondAuthorization: "",
			expectedEqual:       true,
		},
		"should separate different authorization values": {
			firstAuthorization:  "Bearer alice",
			secondAuthorization: "Bearer bob",
		},
		"should separate authorized and anonymous requests": {
			firstAuthorization: "Bearer alice",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			first := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/resource", nil)
			first.Header.Set("Authorization", tc.firstAuthorization)

			second := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/resource", nil)
			second.Header.Set("Authorization", tc.secondAuthorization)

			// WHEN
			firstTargetID := requestTargetID(first)
			secondTargetID := requestTargetID(second)

			// THEN
			if tc.expectedEqual {
				assert.Equal(t, firstTargetID, secondTargetID)
			} else {
				assert.NotEqual(t, firstTargetID, secondTargetID)
			}
		})
	}
}
