// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package requestcontext

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractMethod(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		expect string
		modify func(t *testing.T, header http.Header)
	}{
		{
			"from header",
			http.MethodPatch,
			func(t *testing.T, header http.Header) {
				t.Helper()

				header.Set("X-Forwarded-Method", http.MethodPatch)
			},
		},
		{
			"from request",
			http.MethodDelete,
			func(t *testing.T, header http.Header) { t.Helper() },
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequest(http.MethodDelete, "/foo", nil)
			tc.modify(t, req.Header)

			// WHEN
			method := extractMethod(req)

			// THEN
			assert.Equal(t, tc.expect, method)
		})
	}
}
