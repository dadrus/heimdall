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

package ioprogress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type deadlineResponseWriter struct {
	header         http.Header
	readDeadlines  []time.Time
	writeDeadlines []time.Time
}

func (rw *deadlineResponseWriter) Header() http.Header         { return rw.header }
func (*deadlineResponseWriter) WriteHeader(int)                {}
func (*deadlineResponseWriter) Write(data []byte) (int, error) { return len(data), nil }

func (rw *deadlineResponseWriter) SetReadDeadline(deadline time.Time) error {
	rw.readDeadlines = append(rw.readDeadlines, deadline)

	return nil
}

func (rw *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	rw.writeDeadlines = append(rw.writeDeadlines, deadline)

	return nil
}

func TestHandlerCombinesRequestAndResponsePolicies(t *testing.T) {
	t.Parallel()

	// GIVEN
	rw := &deadlineResponseWriter{header: make(http.Header)}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("request"))
	handler := New(
		zerolog.Nop(),
		WithRequestBodyReadIdleTimeout(time.Second),
		WithResponseWriteIdleTimeout(time.Second),
	)(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		data := make([]byte, 1)
		_, err := req.Body.Read(data)
		assert.NoError(t, err)

		_, err = io.WriteString(rw, "response")
		assert.NoError(t, err)
	}))

	// WHEN
	handler.ServeHTTP(rw, req)

	// THEN
	require.Len(t, rw.readDeadlines, 2)
	assert.False(t, rw.readDeadlines[0].IsZero())
	assert.True(t, rw.readDeadlines[1].IsZero())

	require.Len(t, rw.writeDeadlines, 3)
	assert.False(t, rw.writeDeadlines[0].IsZero())
	assert.True(t, rw.writeDeadlines[1].IsZero())
	assert.False(t, rw.writeDeadlines[2].IsZero())
}
