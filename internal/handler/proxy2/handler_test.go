package proxy2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"

	mocks2 "github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler/mocks"
	mocks3 "github.com/dadrus/heimdall/internal/handler/request/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

func TestHandlerServeHTTP(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc    string
		setup func(*testing.T, *mocks.ExecutorMock, *mocks3.ContextMock, *mocks2.ErrorHandlerMock)
	}{
		{
			uc: "no error",
			setup: func(t *testing.T, exec *mocks.ExecutorMock, ctx *mocks3.ContextMock, eh *mocks2.ErrorHandlerMock) {
				t.Helper()

				mut := mocks.NewURIMutatorMock(t)

				exec.EXPECT().Execute(ctx).Return(mut, nil)
				ctx.EXPECT().Finalize(mut).Return(nil)
			},
		},
		{
			uc: "with error from executor",
			setup: func(t *testing.T, exec *mocks.ExecutorMock, ctx *mocks3.ContextMock, eh *mocks2.ErrorHandlerMock) {
				t.Helper()

				err := errors.New("exec error")

				exec.EXPECT().Execute(ctx).Return(nil, err)
				eh.EXPECT().HandleError(mock.Anything, mock.Anything, err)
			},
		},
		{
			uc: "with error from finalizer",
			setup: func(t *testing.T, exec *mocks.ExecutorMock, ctx *mocks3.ContextMock, eh *mocks2.ErrorHandlerMock) {
				t.Helper()

				err := errors.New("finalizer error")
				mut := mocks.NewURIMutatorMock(t)

				exec.EXPECT().Execute(ctx).Return(mut, nil)
				ctx.EXPECT().Finalize(mut).Return(err)
				eh.EXPECT().HandleError(mock.Anything, mock.Anything, err)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			rcf := mocks3.NewContextFactoryMock(t)
			re := mocks.NewExecutorMock(t)
			rc := mocks3.NewContextMock(t)
			eh := mocks2.NewErrorHandlerMock(t)

			tc.setup(t, re, rc, eh)

			proxy := newHandler(rcf, re, eh)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rw := httptest.NewRecorder()

			rcf.EXPECT().Create(rw, req).Return(rc)

			// WHEN -> THEN expectations are met
			proxy.ServeHTTP(rw, req)
		})
	}
}
