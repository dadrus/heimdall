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

package recovery

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler/mocks"
)

type recordingErrorHandler struct {
	called atomic.Bool
}

func (h *recordingErrorHandler) HandleError(_ http.ResponseWriter, _ *http.Request, _ error) {
	h.called.Store(true)
}

func TestHandlerExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		shouldPanic bool
		err         any
	}{
		"panics with string as error": {true, "string error"},
		"panics with real error type": {true, errors.New("err error")},
		"does not panic":              {false, ""},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			eh := mocks.NewErrorHandlerMock(t)
			srv := httptest.NewServer(
				alice.New(New(eh)).
					ThenFunc(func(rw http.ResponseWriter, _ *http.Request) {
						if tc.shouldPanic {
							eh.EXPECT().HandleError(mock.Anything, mock.Anything, mock.Anything).Run(
								func(rw http.ResponseWriter, _ *http.Request, _ error) {
									rw.WriteHeader(http.StatusInsufficientStorage)
								})

							panic(tc.err)
						}

						rw.WriteHeader(http.StatusOK)
					}))

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				t.Context(), http.MethodGet, srv.URL+"/test", nil)
			require.NoError(t, err)

			// WHEN
			resp, err := srv.Client().Do(req)

			// THEN
			require.NoError(t, err)

			defer resp.Body.Close()

			res, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Empty(t, res)

			if tc.shouldPanic {
				assert.Equal(t, http.StatusInsufficientStorage, resp.StatusCode)
			} else {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	}
}

func TestHandlerPropagatesHTTPAbortHandler(t *testing.T) {
	t.Parallel()

	// GIVEN
	eh := new(recordingErrorHandler)
	srv := httptest.NewServer(
		alice.New(New(eh)).
			ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/abort" {
					panic(http.ErrAbortHandler)
				}

				rw.WriteHeader(http.StatusNoContent)
			}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/abort", nil)
	require.NoError(t, err)

	// WHEN
	resp, err := srv.Client().Do(req) //nolint:bodyclose

	// THEN
	require.False(t, eh.called.Load(), "error handler must not be invoked for http.ErrAbortHandler")
	require.Error(t, err)
	if resp != nil {
		_ = resp.Body.Close()
	}

	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/ok", nil)
	require.NoError(t, err)

	resp, err = srv.Client().Do(req) //nolint:bodyclose
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}
