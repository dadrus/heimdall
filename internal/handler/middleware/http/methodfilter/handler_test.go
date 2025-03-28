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

package methodfilter

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/methodfilter/mocks"
)

//go:generate mockery --srcpkg "net/http" --name Handler --structname HandlerMock

func TestHandler(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		requestMethod string
		filterMethod  string
		setupNext     func(t *testing.T, next *mocks.HandlerMock)
		assert        func(t *testing.T, rec *httptest.ResponseRecorder)
	}{
		"method accepted": {
			requestMethod: http.MethodDelete,
			filterMethod:  http.MethodDelete,
			setupNext: func(t *testing.T, next *mocks.HandlerMock) {
				t.Helper()

				next.EXPECT().ServeHTTP(mock.Anything, mock.Anything)
			},
			assert: func(t *testing.T, _ *httptest.ResponseRecorder) {
				t.Helper()
			},
		},
		"method not allowed": {
			requestMethod: http.MethodDelete,
			filterMethod:  http.MethodGet,
			setupNext: func(t *testing.T, _ *mocks.HandlerMock) {
				t.Helper()
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			next := mocks.NewHandlerMock(t)
			tc.setupNext(t, next)

			handler := New(tc.filterMethod)
			rw := httptest.NewRecorder()

			// WHEN
			handler(next).ServeHTTP(rw, httptest.NewRequest(tc.requestMethod, "http://heimdall.local/foo", nil))

			// THEN
			tc.assert(t, rw)
		})
	}
}
