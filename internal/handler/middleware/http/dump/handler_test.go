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

package dump

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDumpHandlerExecution(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		logLevel zerolog.Level
		assert   func(t *testing.T, logstring string)
	}{
		"debug log level": {
			logLevel: zerolog.DebugLevel,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Empty(t, logs)
			},
		},
		"trace log level": {
			logLevel: zerolog.TraceLevel,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				require.NotEmpty(t, logs)

				lines := strings.Split(logs, "}{")
				require.Len(t, lines, 2)

				var line1 map[string]any
				err := json.Unmarshal([]byte(lines[0]+"}"), &line1)
				require.NoError(t, err)

				assert.Equal(t, "trace", line1["level"])
				assert.Contains(t, line1["message"], "Foobar")

				var line2 map[string]any
				err = json.Unmarshal([]byte("{"+lines[1]), &line2)
				require.NoError(t, err)

				assert.Equal(t, "trace", line2["level"])
				assert.Contains(t, line2["message"], "Barfoo")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb}).Level(tc.logLevel)

			srv := httptest.NewServer(
				alice.New(
					func(next http.Handler) http.Handler {
						return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
							next.ServeHTTP(rw, req.WithContext(logger.WithContext(req.Context())))
						})
					},
					New(),
				).ThenFunc(func(rw http.ResponseWriter, _ *http.Request) {
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte("Barfoo"))
				}))

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				srv.URL+"/test",
				strings.NewReader("Foobar"),
			)
			require.NoError(t, err)

			// WHEN
			resp, err := srv.Client().Do(req)

			// THEN
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			tc.assert(t, tb.CollectedLog())
		})
	}
}
