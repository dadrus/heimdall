package recovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/proxy2/middlewares/errorhandler/mocks"
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
					ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
						if tc.shouldPanic {
							eh.EXPECT().HandleError(mock.Anything, mock.Anything, mock.Anything).Run(
								func(rw http.ResponseWriter, req *http.Request, err error) {
									rw.WriteHeader(http.StatusInsufficientStorage)
								})

							panic(tc.err)
						}

						rw.WriteHeader(http.StatusOK)
					}))

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				context.Background(), http.MethodGet, fmt.Sprintf("%s/test", srv.URL), nil)
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
