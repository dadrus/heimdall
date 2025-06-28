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

package trustedproxy

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestHandlerExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ips        []string
		shouldDrop bool
		warningLog string
	}{
		"bad IP range":                                  {ips: []string{"/128"}, shouldDrop: true, warningLog: "could not be parsed"},
		"single IP trusted":                             {ips: []string{"127.0.0.1"}, shouldDrop: false},
		"trusted IP range":                              {ips: []string{"127.0.0.0/24"}, shouldDrop: false},
		"source in IP range but not trusted IPv4":       {ips: []string{"172.0.0.0/0"}, shouldDrop: false, warningLog: "trusted proxies contains insecure"},
		"source not in IPv6 range and is not trusted 1": {ips: []string{"::/0"}, shouldDrop: true, warningLog: "trusted proxies contains insecure"},
		"source not in IPv6 range and is not trusted 2": {ips: []string{"3209:7473:73ed:a31c:0a08:f214:2434:d5ce/0"}, shouldDrop: true, warningLog: "trusted proxies contains insecure"},
		"source not in IPv4 range":                      {ips: []string{"172.0.0.0/24"}, shouldDrop: true},
		"empty list":                                    {ips: []string{}, shouldDrop: true},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			send := http.Header{
				"X-Forwarded-Proto": []string{"https"},
				"X-Forwarded-Host":  []string{"foobar.com"},
				"X-Forwarded-Path":  []string{"/test"},
				"X-Forwarded-Uri":   []string{"/test?foo=bar"},
				"X-Forwarded-For":   []string{"172.17.1.2"},
				"Forwarded":         []string{"for=172.17.1.2;proto=https"},
				"X-Foo-Bar":         []string{"foo"},
			}

			var received http.Header

			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			srv := httptest.NewServer(
				alice.New(New(logger, tc.ips...)).
					ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
						received = maps.Clone(req.Header)

						rw.WriteHeader(http.StatusGone)
					}))

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				t.Context(), http.MethodGet, srv.URL+"/test", nil)
			require.NoError(t, err)

			req.Header = send

			// WHEN
			resp, err := srv.Client().Do(req)

			// THEN
			require.NoError(t, err)
			resp.Body.Close()

			if tc.shouldDrop {
				require.Empty(t, received.Get("X-Forwarded-Proto"))
				require.Empty(t, received.Get("X-Forwarded-Host"))
				require.Empty(t, received.Get("X-Forwarded-Path"))
				require.Empty(t, received.Get("X-Forwarded-Uri"))
				require.Empty(t, received.Get("X-Forwarded-For"))
				require.Empty(t, received.Get("Forwarded"))
				require.Equal(t, "foo", received.Get("X-Foo-Bar"))
			} else {
				require.Equal(t, send.Get("X-Forwarded-Proto"), received.Get("X-Forwarded-Proto"))
				require.Equal(t, send.Get("X-Forwarded-Host"), received.Get("X-Forwarded-Host"))
				require.Equal(t, send.Get("X-Forwarded-Path"), received.Get("X-Forwarded-Path"))
				require.Equal(t, send.Get("X-Forwarded-Uri"), received.Get("X-Forwarded-Uri"))
				require.Equal(t, send.Get("X-Forwarded-For"), received.Get("X-Forwarded-For"))
				require.Equal(t, send.Get("Forwarded"), received.Get("Forwarded"))
				require.Equal(t, send.Get("X-Foo-Bar"), received.Get("X-Foo-Bar"))
			}

			logs := tb.CollectedLog()
			if len(logs) != 0 {
				require.NotEmpty(t, tc.warningLog, "logs contain warnings, but no warnings are expected")
				assert.Contains(t, logs, tc.warningLog)
			}
		})
	}
}
