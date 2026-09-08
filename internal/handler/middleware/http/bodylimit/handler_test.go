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

	"github.com/dadrus/heimdall/internal/pipeline"
)

type errorHandlerFunc func(http.ResponseWriter, *http.Request, error)

func (f errorHandlerFunc) HandleError(rw http.ResponseWriter, req *http.Request, err error) {
	f(rw, req, err)
}

func TestHandlerExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		maxSize bytesize.ByteSize
		setup   func(*http.Request)
		assert  func(t *testing.T, statusCode int, nextCalled bool, readErr error, handledErr error)
	}{
		"limit disabled": {
			maxSize: 0,
			setup: func(req *http.Request) {
				req.Body = io.NopCloser(strings.NewReader("123456"))
				req.ContentLength = 6
			},
			assert: func(t *testing.T, statusCode int, nextCalled bool, readErr error, handledErr error) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, statusCode)
				assert.True(t, nextCalled)
				require.NoError(t, readErr)
				require.NoError(t, handledErr)
			},
		},
		"nil body": {
			maxSize: 5 * bytesize.B,
			setup: func(req *http.Request) {
				req.Body = nil
				req.ContentLength = 0
			},
			assert: func(t *testing.T, statusCode int, nextCalled bool, readErr error, handledErr error) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, statusCode)
				assert.True(t, nextCalled)
				require.NoError(t, readErr)
				require.NoError(t, handledErr)
			},
		},
		"body below limit": {
			maxSize: 5 * bytesize.B,
			setup: func(req *http.Request) {
				req.Body = io.NopCloser(strings.NewReader("1234"))
				req.ContentLength = 4
			},
			assert: func(t *testing.T, statusCode int, nextCalled bool, readErr error, handledErr error) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, statusCode)
				assert.True(t, nextCalled)
				require.NoError(t, readErr)
				require.NoError(t, handledErr)
			},
		},
		"body exactly at limit": {
			maxSize: 5 * bytesize.B,
			setup: func(req *http.Request) {
				req.Body = io.NopCloser(strings.NewReader("12345"))
				req.ContentLength = 5
			},
			assert: func(t *testing.T, statusCode int, nextCalled bool, readErr error, handledErr error) {
				t.Helper()

				assert.Equal(t, http.StatusNoContent, statusCode)
				assert.True(t, nextCalled)
				require.NoError(t, readErr)
				require.NoError(t, handledErr)
			},
		},
		"body above limit with known content length": {
			maxSize: 5 * bytesize.B,
			setup: func(req *http.Request) {
				req.Body = io.NopCloser(strings.NewReader("123456"))
				req.ContentLength = 6
			},
			assert: func(t *testing.T, statusCode int, nextCalled bool, readErr error, handledErr error) {
				t.Helper()

				assert.Equal(t, http.StatusRequestEntityTooLarge, statusCode)
				assert.False(t, nextCalled)
				require.NoError(t, readErr)
				require.ErrorIs(t, handledErr, pipeline.ErrRequestBodyTooLarge)
			},
		},
		"body above limit with unknown content length": {
			maxSize: 5 * bytesize.B,
			setup: func(req *http.Request) {
				req.Body = io.NopCloser(strings.NewReader("123456"))
				req.ContentLength = -1
			},
			assert: func(t *testing.T, statusCode int, nextCalled bool, readErr error, handledErr error) {
				t.Helper()

				assert.Equal(t, http.StatusRequestEntityTooLarge, statusCode)
				assert.True(t, nextCalled)
				require.NoError(t, handledErr)

				var maxBytesErr *http.MaxBytesError

				require.ErrorAs(t, readErr, &maxBytesErr)
				assert.Equal(t, int64(5), maxBytesErr.Limit)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			// GIVEN
			var (
				nextCalled bool
				readErr    error
				handledErr error
			)

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"http://heimdall.local/test",
				nil,
			)
			tc.setup(req)

			eh := errorHandlerFunc(func(rw http.ResponseWriter, _ *http.Request, err error) {
				handledErr = err
				rw.WriteHeader(http.StatusRequestEntityTooLarge)
			})

			handler := alice.New(New(tc.maxSize, eh)).
				ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
					nextCalled = true

					if req.Body != nil {
						_, readErr = io.ReadAll(req.Body)
					}

					if readErr != nil {
						rw.WriteHeader(http.StatusRequestEntityTooLarge)

						return
					}

					rw.WriteHeader(http.StatusNoContent)
				})

			rw := httptest.NewRecorder()

			// WHEN
			handler.ServeHTTP(rw, req)

			// THEN
			tc.assert(t, rw.Code, nextCalled, readErr, handledErr)
		})
	}
}
