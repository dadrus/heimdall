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

	"github.com/stretchr/testify/mock"

	mocks2 "github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler/mocks"
	mocks3 "github.com/dadrus/heimdall/internal/handler/requestcontext/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

func TestHandlerServeHTTP(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		setup func(*testing.T, *mocks.ExecutorMock, *mocks3.ContextMock, *mocks2.ErrorHandlerMock)
	}{
		"no error": {
			setup: func(t *testing.T, exec *mocks.ExecutorMock, ctx *mocks3.ContextMock, _ *mocks2.ErrorHandlerMock) {
				t.Helper()

				upstream := mocks.NewBackendMock(t)

				exec.EXPECT().Execute(ctx).Return(upstream, nil)
				ctx.EXPECT().Finalize(upstream).Return(nil)
			},
		},
		"with error from executor": {
			setup: func(t *testing.T, exec *mocks.ExecutorMock, ctx *mocks3.ContextMock, eh *mocks2.ErrorHandlerMock) {
				t.Helper()

				err := errors.New("exec error")

				exec.EXPECT().Execute(ctx).Return(nil, err)
				eh.EXPECT().HandleError(mock.Anything, mock.Anything, err)
			},
		},
		"with error from finalizer": {
			setup: func(t *testing.T, exec *mocks.ExecutorMock, ctx *mocks3.ContextMock, eh *mocks2.ErrorHandlerMock) {
				t.Helper()

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

			tc.setup(t, re, rc, eh)

			proxy := NewHandler(rcf, re, eh)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rw := httptest.NewRecorder()

			rcf.EXPECT().Create(rw, req).Return(rc)

			// WHEN -> THEN expectations are met
			proxy.ServeHTTP(rw, req)
		})
	}
}
