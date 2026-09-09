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

package service

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	mocks "github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler/mocks"
)

type requestCoordinatorFunc func(*http.Request, http.ResponseWriter) (struct{}, error)

func (f requestCoordinatorFunc) Handle(req *http.Request, rw http.ResponseWriter) (struct{}, error) {
	return f(req, rw)
}

func TestHandlerServeHTTP(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err   error
		setup func(*testing.T, *mocks.ErrorHandlerMock, http.ResponseWriter, *http.Request)
	}{
		"no error": {
			setup: func(t *testing.T, _ *mocks.ErrorHandlerMock, _ http.ResponseWriter, _ *http.Request) {
				t.Helper()
			},
		},
		"with error": {
			err: assert.AnError,
			setup: func(t *testing.T, eh *mocks.ErrorHandlerMock, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				eh.EXPECT().HandleError(rw, req, assert.AnError)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)
			rw := httptest.NewRecorder()

			eh := mocks.NewErrorHandlerMock(t)
			tc.setup(t, eh, rw, req)

			coordinator := requestCoordinatorFunc(func(actualReq *http.Request, actualRW http.ResponseWriter) (struct{}, error) {
				assert.Same(t, req, actualReq)
				assert.Same(t, rw, actualRW)

				return struct{}{}, tc.err
			})

			handler := NewHandler(coordinator, eh)

			// WHEN -> THEN expectations are met
			handler.ServeHTTP(rw, req)
		})
	}
}
