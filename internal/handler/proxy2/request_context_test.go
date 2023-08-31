package proxy2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler/mocks"
)

func TestRequestContextRequestClientIPs(t *testing.T) {
	t.Parallel()
}

func TestRequestContextError(t *testing.T) {
	t.Parallel()

	testErr := errors.New("test error")
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "https://foo.bar/test", nil)

	eh := mocks.NewErrorHandlerMock(t)
	eh.EXPECT().HandleError(rw, req, testErr)

	factory := newRequestContextFactory(eh, nil, 0)
	rc := factory.Create(rw, req)

	// WHEN -> THEN expectations are met
	rc.Error(testErr)
}
