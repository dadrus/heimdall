// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package requestlimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/accesscontext"
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
		handler := New(0)(next)

		// THEN
		assert.Same(t, next, handler)
	})

	t.Run("rejects request while capacity is exhausted and releases capacity afterwards", func(t *testing.T) {
		// GIVEN
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

		handler := New(1)(next)

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

		secondResponse := httptest.NewRecorder()

		// WHEN
		handler.ServeHTTP(
			secondResponse,
			httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil),
		)

		// THEN
		assert.Equal(t, http.StatusServiceUnavailable, secondResponse.Code)
		assert.Empty(t, secondResponse.Body.String())

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

	t.Run("uses configured reject handler", func(t *testing.T) {
		// GIVEN
		requestEntered := make(chan struct{}, 1)
		releaseRequest := make(chan struct{})

		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requestEntered <- struct{}{}
			<-releaseRequest
		})

		var rejectionErr error
		handler := New(1, WithRejectHandler(func(rw http.ResponseWriter, req *http.Request) {
			rejectionErr = accesscontext.Error(req.Context())
			rw.WriteHeader(http.StatusTeapot)
		}))(next)

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

		response := httptest.NewRecorder()
		ctx := accesscontext.New(t.Context())

		// WHEN
		handler.ServeHTTP(
			response,
			httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil),
		)

		// THEN
		assert.Equal(t, http.StatusTeapot, response.Code)
		require.Error(t, rejectionErr)
		assert.Equal(t, "service overloaded", rejectionErr.Error())

		close(releaseRequest)
		<-firstDone
	})
}
