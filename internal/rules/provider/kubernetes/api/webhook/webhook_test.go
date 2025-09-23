package webhook

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/x"
)

func TestWebhookServeHTTP(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		req            *http.Request
		configureMocks func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]])
		assert         func(t *testing.T, resp *http.Response)
	}{
		"unsupported content-type": {
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`foo`))
				req.Header.Set("Content-Type", "text/plain")

				return req
			}(),
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
		},
		"request unmarshalling failed": {
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")

				return req
			}(),
			configureMocks: func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]]) {
				t.Helper()

				rm.EXPECT().Decode(mock.Anything).Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			},
		},
		"response marshalling failed": {
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")

				return req
			}(),
			configureMocks: func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]]) {
				t.Helper()

				req := NewRequestMock(t)
				resp := NewResponseMock[*RequestMock](t)

				type Bad struct {
					F func() // functions cannot be marshaled
				}

				rm.EXPECT().Decode(mock.Anything).Return(req, nil)
				hm.EXPECT().Handle(mock.Anything, req).Return(resp)
				resp.EXPECT().Complete(req).Return()
				rm.EXPECT().WrapResponse(resp).Return(&Bad{})
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			},
		},
		"successful execution without setting timeout": {
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")

				return req
			}(),
			configureMocks: func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]]) {
				t.Helper()

				req := NewRequestMock(t)
				resp := NewResponseMock[*RequestMock](t)

				rm.EXPECT().Decode(mock.Anything).Return(req, nil)
				hm.EXPECT().Handle(mock.Anything, req).Return(resp)
				resp.EXPECT().Complete(req).Return()
				rm.EXPECT().WrapResponse(resp).Return("foo")
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		"request timed out": {
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/?timeout=10ms", bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")

				return req
			}(),
			configureMocks: func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]]) {
				t.Helper()

				req := NewRequestMock(t)
				resp := NewResponseMock[*RequestMock](t)

				rm.EXPECT().Decode(mock.Anything).Return(req, nil)
				hm.EXPECT().Handle(mock.Anything, req).Return(resp)
				resp.EXPECT().Complete(req).Run(func(_ *RequestMock) {
					time.Sleep(20 * time.Millisecond)
				})
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			},
		},
		"successful execution with timeout set": {
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/?timeout=10ms", bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")

				return req
			}(),
			configureMocks: func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]]) {
				t.Helper()

				req := NewRequestMock(t)
				resp := NewResponseMock[*RequestMock](t)

				rm.EXPECT().Decode(mock.Anything).Return(req, nil)
				hm.EXPECT().Handle(mock.Anything, req).Return(resp)
				resp.EXPECT().Complete(req).Return()
				rm.EXPECT().WrapResponse(resp).Return("foo")
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		"invalid timeout set and not considered during execution": {
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/?timeout=foo", bytes.NewBufferString(`{}`))
				req.Header.Set("Content-Type", "application/json")

				return req
			}(),
			configureMocks: func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]]) {
				t.Helper()

				req := NewRequestMock(t)
				resp := NewResponseMock[*RequestMock](t)

				rm.EXPECT().Decode(mock.Anything).Return(req, nil)
				hm.EXPECT().Handle(mock.Anything, req).Return(resp)
				resp.EXPECT().Complete(req).Return()
				rm.EXPECT().WrapResponse(resp).Return("foo")
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			hm := NewHandlerMock[*RequestMock, *ResponseMock[*RequestMock]](t)
			rvm := NewReviewMock[*RequestMock, *ResponseMock[*RequestMock]](t)

			configureMocks := x.IfThenElse(
				tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, hm *HandlerMock[*RequestMock, *ResponseMock[*RequestMock]], rm *ReviewMock[*RequestMock, *ResponseMock[*RequestMock]]) {
					t.Helper()
				})

			configureMocks(t, hm, rvm)

			wh := New[*RequestMock, *ResponseMock[*RequestMock]](hm, rvm)

			rr := httptest.NewRecorder()
			wh.ServeHTTP(rr, tc.req)

			tc.assert(t, rr.Result())
		})
	}
}
