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

func TestNewCacheableRequest(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		connectionHeaders        []string
		expectedConnectionFields map[string]struct{}
	}{
		"should derive cache request without connection-specific fields": {},
		"should collect and canonicalize connection-specific fields": {
			connectionHeaders: []string{
				"keep-alive, X-Custom-Field",
				"x-custom-field, upgrade",
			},
			expectedConnectionFields: map[string]struct{}{
				"Keep-Alive":     {},
				"Upgrade":        {},
				"X-Custom-Field": {},
			},
		},
		"should ignore invalid connection field names": {
			connectionHeaders: []string{
				"X-Valid, invalid field, @invalid, Te",
			},
			expectedConnectionFields: map[string]struct{}{
				"Te":      {},
				"X-Valid": {},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://user:password@example.com/resource?foo=bar",
				nil,
			)
			req.Host = "tenant.example.com"

			for _, value := range tc.connectionHeaders {
				req.Header.Add("Connection", value)
			}

			expectedTargetID := requestTargetID(req)
			expectedIndexKey := variantIndexKey(expectedTargetID)

			// WHEN
			actual := newCacheableRequest(req)

			// THEN
			assert.Same(t, req, actual.request)
			assert.Equal(t, expectedTargetID, actual.targetID)
			assert.Equal(t, expectedIndexKey, actual.indexKey)
			assert.Equal(t, tc.expectedConnectionFields, actual.connectionFields)
		})
	}
}

func TestCacheableRequestSelector(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		vary []string
	}{
		"should create selector without vary fields": {},
		"should create selector for a single vary field": {
			vary: []string{"Accept-Language"},
		},
		"should create selector for multiple vary fields": {
			vary: []string{"Accept-Encoding", "Accept-Language", "X-Tenant"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://example.com/resource",
				nil,
			)
			req.Header["Accept-Encoding"] = []string{"gzip", "br"}
			req.Header["Accept-Language"] = []string{"de"}
			req.Header["X-Tenant"] = []string{"tenant-a"}
			cacheReq := newCacheableRequest(req)
			expected := requestVariantSelector(req, tc.vary)

			// WHEN
			actual := cacheReq.selector(tc.vary)

			// THEN
			assert.Equal(t, expected, actual)
		})
	}
}
