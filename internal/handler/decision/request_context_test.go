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

package decision

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/handler/requestcontext"
)

func TestRequestContextFinalize(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		code   int
		setup  func(t *testing.T, rc requestcontext.Context)
		assert func(t *testing.T, err error, rec *httptest.ResponseRecorder)
	}{
		{
			uc: "finalize returns error",
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.SetPipelineError(errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *httptest.ResponseRecorder) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:   "only response code is set",
			code: http.StatusNoContent,
			setup: func(t *testing.T, _ requestcontext.Context) {
				t.Helper()
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Empty(t, rec.Header())
				assert.Equal(t, http.StatusNoContent, rec.Code)
			},
		},
		{
			uc:   "only response code and headers are set",
			code: http.StatusMultiStatus,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("X-Foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)
				assert.Equal(t, "bar", rec.Header().Get("X-Foo"))
				assert.Equal(t, http.StatusMultiStatus, rec.Code)
			},
		},
		{
			uc:   "only response code and cookies are set",
			code: http.StatusAccepted,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddCookieForUpstream("x-foo", "bar")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 1)
				assert.Equal(t, "x-foo=bar", rec.Header().Get("Set-Cookie"))
				assert.Equal(t, http.StatusAccepted, rec.Code)
			},
		},
		{
			uc:   "everything is set",
			code: http.StatusOK,
			setup: func(t *testing.T, rc requestcontext.Context) {
				t.Helper()

				rc.AddHeaderForUpstream("X-Foo", "bar")
				rc.AddHeaderForUpstream("X-Bar", "foo")
				rc.AddCookieForUpstream("x-foo", "bar")
				rc.AddCookieForUpstream("x-bar", "foo")
			},
			assert: func(t *testing.T, err error, rec *httptest.ResponseRecorder) {
				t.Helper()

				require.NoError(t, err)

				assert.Len(t, rec.Header(), 3)
				assert.Contains(t, rec.Header().Values("Set-Cookie"), "x-bar=foo")
				assert.Contains(t, rec.Header().Values("Set-Cookie"), "x-foo=bar")
				assert.Equal(t, "bar", rec.Header().Get("X-Foo"))
				assert.Equal(t, "foo", rec.Header().Get("X-Bar"))
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			rw := httptest.NewRecorder()

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://heimdall.local/foo", nil)
			require.NoError(t, err)

			reqCtx := newContextFactory(tc.code).Create(rw, req)
			tc.setup(t, reqCtx)

			// WHEN
			err = reqCtx.Finalize(nil)

			// THEN
			tc.assert(t, err, rw)
		})
	}
}
