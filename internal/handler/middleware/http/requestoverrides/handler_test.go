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

package requestoverrides

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlerExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		host       string
		header     http.Header
		wantStatus int
		wantNext   bool
	}{
		"valid host": {
			host:       "heimdall.local",
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"valid host with port": {
			host:       "heimdall.local:8080",
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"valid IPv6 host": {
			host:       "[2001:db8::1]:8080",
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"valid forwarded host": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Host": {"upstream.local"},
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"valid forwarded host with port": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Host": {"upstream.local:8443"},
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"valid singleton request override headers": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Host":   {"upstream.local"},
				"X-Forwarded-Method": {"GET"},
				"X-Forwarded-Proto":  {"https"},
				"X-Forwarded-Uri":    {"/foo?bar=baz"},
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"empty host": {
			host:       "",
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"host with comma injection": {
			host:       "evil.com,for=127.0.0.1",
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"host with semicolon injection": {
			host:       "evil.com;for=127.0.0.1",
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"host with CRLF injection": {
			host:       "evil.com\r\nX-Injected: true",
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"forwarded host with comma injection": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Host": {"evil.com,for=127.0.0.1"},
			},
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"forwarded host with semicolon injection": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Host": {"evil.com;for=127.0.0.1"},
			},
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"multiple forwarded host values": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Host": {"upstream.local", "evil.local"},
			},
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"multiple forwarded method values": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Method": {"GET", "POST"},
			},
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"multiple forwarded proto values": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Proto": {"http", "https"},
			},
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		"multiple forwarded uri values": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-Uri": {"/foo", "/bar"},
			},
			wantStatus: http.StatusBadRequest,
			wantNext:   false,
		},
		// these tests are for documentation purposes only
		"multiple x-forwarded-for values are ignored": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-For": {"192.0.2.1", "198.51.100.1"},
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"comma separated x-forwarded-for is ignored": {
			host: "heimdall.local",
			header: http.Header{
				"X-Forwarded-For": {"192.0.2.1, 198.51.100.1"},
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"multiple forwarded values are accepted": {
			host: "heimdall.local",
			header: http.Header{
				"Forwarded": {"for=192.0.2.1", "for=198.51.100.1"},
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		"comma separated forwarded is ignored": {
			host: "heimdall.local",
			header: http.Header{
				"Forwarded": {"for=192.0.2.1, for=198.51.100.1"},
			},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			nextCalled := false
			handler := alice.New(New()).ThenFunc(func(rw http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				rw.WriteHeader(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodGet, "http://heimdall.local/test", nil)
			req.Host = tc.host
			req.Header = tc.header.Clone()

			rw := httptest.NewRecorder()

			// WHEN
			handler.ServeHTTP(rw, req)

			// THEN
			require.Equal(t, tc.wantStatus, rw.Code)
			assert.Equal(t, tc.wantNext, nextCalled)
		})
	}
}
