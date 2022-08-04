package errorhandler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

func TestDefaultErrorHandler(t *testing.T) {
	t.Parallel()

	var appError error

	app := fiber.New()
	app.Use(New(false))
	app.Get("test", func(ctx *fiber.Ctx) error { return appError })

	for _, tc := range []struct {
		uc             string
		serverError    error
		responseCode   int
		assertResponse func(t *testing.T, response *http.Response)
	}{
		{
			uc:           "no error",
			serverError:  nil,
			responseCode: http.StatusOK,
		},
		{
			uc:           "authentication error",
			serverError:  heimdall.ErrAuthentication,
			responseCode: http.StatusUnauthorized,
		},
		{
			uc:           "authorization error",
			serverError:  heimdall.ErrAuthorization,
			responseCode: http.StatusForbidden,
		},
		{
			uc:           "communication timeout",
			serverError:  heimdall.ErrCommunicationTimeout,
			responseCode: http.StatusBadGateway,
		},
		{
			uc:           "communication error",
			serverError:  heimdall.ErrCommunication,
			responseCode: http.StatusBadGateway,
		},
		{
			uc:           "argument error",
			serverError:  heimdall.ErrArgument,
			responseCode: http.StatusBadRequest,
		},
		{
			uc:           "method not allowed error",
			serverError:  heimdall.ErrMethodNotAllowed,
			responseCode: http.StatusMethodNotAllowed,
		},
		{
			uc:           "no rule found error",
			serverError:  heimdall.ErrNoRuleFound,
			responseCode: http.StatusNotFound,
		},
		{
			uc:           "internal error",
			serverError:  heimdall.ErrInternal,
			responseCode: http.StatusInternalServerError,
		},
		{
			uc: "redirect with see other",
			serverError: &heimdall.RedirectError{
				RedirectTo: &url.URL{Scheme: "http", Host: "foo.bar.local", Path: "foobar"},
				Code:       http.StatusSeeOther,
			},
			assertResponse: func(t *testing.T, response *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusSeeOther, response.StatusCode)
				assert.Equal(t, "http://foo.bar.local/foobar", response.Header.Get("Location"))
			},
		},
		{
			uc: "redirect with found",
			serverError: &heimdall.RedirectError{
				RedirectTo: &url.URL{Scheme: "http", Host: "foo.bar.local", Path: "foobar"},
				Code:       http.StatusFound,
			},
			assertResponse: func(t *testing.T, response *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusFound, response.StatusCode)
				assert.Equal(t, "http://foo.bar.local/foobar", response.Header.Get("Location"))
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			appError = tc.serverError
			assertResponse := x.IfThenElse(
				tc.assertResponse != nil,
				tc.assertResponse,
				func(t *testing.T, response *http.Response) {
					t.Helper()

					assert.Equal(t, tc.responseCode, response.StatusCode)
				})

			// WHEN
			resp, err := app.Test(httptest.NewRequest("GET", "/test", nil))

			// THEN
			require.NoError(t, err)
			defer resp.Body.Close()

			assertResponse(t, resp)
			data, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Len(t, data, 0)
		})
	}
}

func TestVerboseErrorHandler(t *testing.T) {
	t.Parallel()

	var appError error

	app := fiber.New()
	app.Use(New(true))
	app.Get("test", func(ctx *fiber.Ctx) error { return appError })

	for _, tc := range []struct {
		uc             string
		serverError    error
		responseCode   int
		assertResponse func(t *testing.T, response *http.Response)
	}{
		{
			uc:          "no error",
			serverError: nil,
			assertResponse: func(t *testing.T, response *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, response.StatusCode)

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		{
			uc:           "authentication error",
			serverError:  heimdall.ErrAuthentication,
			responseCode: http.StatusUnauthorized,
		},
		{
			uc:           "authorization error",
			serverError:  heimdall.ErrAuthorization,
			responseCode: http.StatusForbidden,
		},
		{
			uc:           "communication timeout",
			serverError:  heimdall.ErrCommunicationTimeout,
			responseCode: http.StatusBadGateway,
		},
		{
			uc:           "communication error",
			serverError:  heimdall.ErrCommunication,
			responseCode: http.StatusBadGateway,
		},
		{
			uc:           "argument error",
			serverError:  heimdall.ErrArgument,
			responseCode: http.StatusBadRequest,
		},
		{
			uc:           "method not allowed error",
			serverError:  heimdall.ErrMethodNotAllowed,
			responseCode: http.StatusMethodNotAllowed,
		},
		{
			uc:           "no rule found error",
			serverError:  heimdall.ErrNoRuleFound,
			responseCode: http.StatusNotFound,
		},
		{
			uc:           "internal error",
			serverError:  heimdall.ErrInternal,
			responseCode: http.StatusInternalServerError,
		},
		{
			uc: "redirect with see other",
			serverError: &heimdall.RedirectError{
				RedirectTo: &url.URL{Scheme: "http", Host: "foo.bar.local", Path: "foobar"},
				Code:       http.StatusSeeOther,
			},
			assertResponse: func(t *testing.T, response *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusSeeOther, response.StatusCode)
				assert.Equal(t, "http://foo.bar.local/foobar", response.Header.Get("Location"))

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
		{
			uc: "redirect with found",
			serverError: &heimdall.RedirectError{
				RedirectTo: &url.URL{Scheme: "http", Host: "foo.bar.local", Path: "foobar"},
				Code:       http.StatusFound,
			},
			assertResponse: func(t *testing.T, response *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusFound, response.StatusCode)
				assert.Equal(t, "http://foo.bar.local/foobar", response.Header.Get("Location"))

				data, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				assert.Empty(t, data)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			appError = tc.serverError
			assertResponse := x.IfThenElse(
				tc.assertResponse != nil,
				tc.assertResponse,
				func(t *testing.T, response *http.Response) {
					t.Helper()

					assert.Equal(t, tc.responseCode, response.StatusCode)
					data, err := io.ReadAll(response.Body)
					require.NoError(t, err)
					assert.NotEmpty(t, data)
				})

			// WHEN
			resp, err := app.Test(httptest.NewRequest("GET", "/test", nil))

			// THEN
			require.NoError(t, err)
			defer resp.Body.Close()

			assertResponse(t, resp)
		})
	}
}
