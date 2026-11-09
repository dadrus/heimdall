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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks2 "github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler/mocks"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	mocks3 "github.com/dadrus/heimdall/internal/handler/requestcontext/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

func TestHandlerServeHTTP(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup func(
			*testing.T,
			*mocks3.ContextFactoryMock,
			*mocks.ExecutorMock,
			*mocks3.ContextMock,
			*mocks2.ErrorHandlerMock,
			*httptest.ResponseRecorder,
			*http.Request,
		)
		assert func(*testing.T, *httptest.ResponseRecorder)
	}{
		"no error": {
			setup: func(
				t *testing.T,
				factory *mocks3.ContextFactoryMock,
				exec *mocks.ExecutorMock,
				ctx *mocks3.ContextMock,
				_ *mocks2.ErrorHandlerMock,
				rw *httptest.ResponseRecorder,
				req *http.Request,
			) {
				t.Helper()

				factory.EXPECT().Create(rw, req).Return(ctx, nil)
				factory.EXPECT().Destroy(ctx)

				upstream := mocks.NewBackendMock(t)

				exec.EXPECT().Execute(ctx).Return(upstream, nil)
				ctx.EXPECT().Finalize(upstream).Return(nil)
			},
		},
		"invalid request target": {
			setup: func(
				t *testing.T,
				factory *mocks3.ContextFactoryMock,
				_ *mocks.ExecutorMock,
				_ *mocks3.ContextMock,
				_ *mocks2.ErrorHandlerMock,
				rw *httptest.ResponseRecorder,
				req *http.Request,
			) {
				t.Helper()

				factory.EXPECT().Create(rw, req).Return(nil, requestcontext.ErrInvalidForwardedURI)
			},
			assert: func(t *testing.T, rw *httptest.ResponseRecorder) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, rw.Code)
			},
		},
		"initialization fails unexpectedly": {
			setup: func(
				t *testing.T,
				factory *mocks3.ContextFactoryMock,
				_ *mocks.ExecutorMock,
				_ *mocks3.ContextMock,
				eh *mocks2.ErrorHandlerMock,
				rw *httptest.ResponseRecorder,
				req *http.Request,
			) {
				t.Helper()

				err := errors.New("unexpected context error")

				factory.EXPECT().Create(rw, req).Return(nil, err)
				eh.EXPECT().HandleError(mock.Anything, mock.Anything, err)
			},
		},
		"with error from executor": {
			setup: func(
				t *testing.T,
				factory *mocks3.ContextFactoryMock,
				exec *mocks.ExecutorMock,
				ctx *mocks3.ContextMock,
				eh *mocks2.ErrorHandlerMock,
				rw *httptest.ResponseRecorder,
				req *http.Request,
			) {
				t.Helper()

				factory.EXPECT().Create(rw, req).Return(ctx, nil)
				factory.EXPECT().Destroy(ctx)

				err := errors.New("exec error")

				exec.EXPECT().Execute(ctx).Return(nil, err)
				eh.EXPECT().HandleError(mock.Anything, mock.Anything, err)
			},
		},
		"with error from finalizer": {
			setup: func(
				t *testing.T,
				factory *mocks3.ContextFactoryMock,
				exec *mocks.ExecutorMock,
				ctx *mocks3.ContextMock,
				eh *mocks2.ErrorHandlerMock,
				rw *httptest.ResponseRecorder,
				req *http.Request,
			) {
				t.Helper()

				factory.EXPECT().Create(rw, req).Return(ctx, nil)
				factory.EXPECT().Destroy(ctx)

				err := errors.New("finalizer error")
				upstream := mocks.NewBackendMock(t)

				exec.EXPECT().Execute(ctx).Return(upstream, nil)
				ctx.EXPECT().Finalize(upstream).Return(err)
				eh.EXPECT().HandleError(mock.Anything, mock.Anything, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			rcf := mocks3.NewContextFactoryMock(t)
			re := mocks.NewExecutorMock(t)
			rc := mocks3.NewContextMock(t)
			eh := mocks2.NewErrorHandlerMock(t)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)
			rw := httptest.NewRecorder()

			tc.setup(t, rcf, re, rc, eh, rw, req)

			proxy := NewHandler(rcf, re, eh)

			// WHEN -> THEN expectations are met
			proxy.ServeHTTP(rw, req)
			if tc.assert != nil {
				tc.assert(t, rw)
			}
		})
	}
}
