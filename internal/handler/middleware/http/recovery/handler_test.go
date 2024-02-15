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
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler/mocks"
)

func TestHandlerExecution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		shouldPanic bool
		err         any
	}{
		{"panics with string as error", true, "string error"},
		{"panics with real error type", true, errors.New("err error")},
		{"does not panic", false, ""},
	} {
		t.Run(tc.uc, func(t *testing.T) {
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
				context.Background(), http.MethodGet, srv.URL+"/test", nil)
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
