package requestlimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	errorhandlermocks "github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler/mocks"
	"github.com/dadrus/heimdall/internal/pipeline"
)

type handlerRecorder struct {
	called bool
}

func (r *handlerRecorder) ServeHTTP(http.ResponseWriter, *http.Request) {
	r.called = true
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("disabled limit returns next handler unchanged", func(t *testing.T) {
		// GIVEN
		next := &handlerRecorder{}

		// WHEN
		handler := New(0, errorhandlermocks.NewErrorHandlerMock(t))(next)

		// THEN
		assert.Same(t, next, handler)
	})

	t.Run("rejects request while capacity is exhausted and releases capacity afterwards", func(t *testing.T) {
		// GIVEN
		eh := errorhandlermocks.NewErrorHandlerMock(t)

		requestEntered := make(chan struct{}, 2)
		releaseRequest := make(chan struct{})

		var releaseOnce sync.Once
		releaseRequests := func() {
			releaseOnce.Do(func() {
				close(releaseRequest)
			})
		}
		t.Cleanup(releaseRequests)

		next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			requestEntered <- struct{}{}

			<-releaseRequest

			rw.WriteHeader(http.StatusNoContent)
		})

		handler := New(1, eh)(next)

		firstDone := make(chan struct{})

		go func() {
			defer close(firstDone)

			handler.ServeHTTP(
				httptest.NewRecorder(),
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil),
			)
		}()

		select {
		case <-requestEntered:
		case <-time.After(time.Second):
			require.FailNow(t, "first request did not enter handler")
		}

		secondRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		secondResponse := httptest.NewRecorder()

		eh.EXPECT().
			HandleError(secondResponse, secondRequest, pipeline.ErrTooManyRequests).
			Return()

		// WHEN
		handler.ServeHTTP(secondResponse, secondRequest)

		// THEN
		select {
		case <-requestEntered:
			require.Fail(t, "request entered handler while capacity was exhausted")
		default:
		}

		// WHEN
		releaseRequests()

		select {
		case <-firstDone:
		case <-time.After(time.Second):
			require.FailNow(t, "first request did not complete")
		}

		thirdResponse := httptest.NewRecorder()

		handler.ServeHTTP(
			thirdResponse,
			httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil),
		)

		// THEN
		assert.Equal(t, http.StatusNoContent, thirdResponse.Code)
	})
}
