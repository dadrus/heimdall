// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package bodylimit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inhies/go-bytesize"
	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlerExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		maxSize       bytesize.ByteSize
		body          string
		contentLength int64
		wantStatus    int
		wantNext      bool
		wantReadError bool
	}{
		"limit disabled": {
			maxSize:       0,
			body:          "123456",
			contentLength: 6,
			wantStatus:    http.StatusNoContent,
			wantNext:      true,
		},
		"body below limit": {
			maxSize:       5 * bytesize.B,
			body:          "1234",
			contentLength: 4,
			wantStatus:    http.StatusNoContent,
			wantNext:      true,
		},
		"body exactly at limit": {
			maxSize:       5 * bytesize.B,
			body:          "12345",
			contentLength: 5,
			wantStatus:    http.StatusNoContent,
			wantNext:      true,
		},
		"body above limit with known content length": {
			maxSize:       5 * bytesize.B,
			body:          "123456",
			contentLength: 6,
			wantStatus:    http.StatusRequestEntityTooLarge,
			wantNext:      false,
		},
		"body above limit with unknown content length": {
			maxSize:       5 * bytesize.B,
			body:          "123456",
			contentLength: -1,
			wantStatus:    http.StatusRequestEntityTooLarge,
			wantNext:      true,
			wantReadError: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			var (
				nextCalled bool
				readErr    error
			)

			handler := alice.New(New(tc.maxSize)).
				ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
					nextCalled = true

					_, readErr = io.ReadAll(req.Body)
					if readErr != nil {
						rw.WriteHeader(http.StatusRequestEntityTooLarge)

						return
					}

					rw.WriteHeader(http.StatusNoContent)
				})

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://heimdall.local/test",
				strings.NewReader(tc.body),
			)
			req.ContentLength = tc.contentLength

			rw := httptest.NewRecorder()

			// WHEN
			handler.ServeHTTP(rw, req)

			// THEN
			assert.Equal(t, tc.wantStatus, rw.Code)
			assert.Equal(t, tc.wantNext, nextCalled)

			if tc.wantReadError {
				require.Error(t, readErr)

				var maxBytesErr *http.MaxBytesError
				require.ErrorAs(t, readErr, &maxBytesErr)
				assert.Equal(t, int64(tc.maxSize), maxBytesErr.Limit)
			} else {
				require.NoError(t, readErr)
			}
		})
	}
}
