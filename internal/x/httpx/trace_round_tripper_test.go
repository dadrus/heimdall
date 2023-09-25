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

package httpx

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/httpx/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

//go:generate mockery --srcpkg "net/http" --name RoundTripper --structname RoundTripperMock

func TestTraceRoundTripperRoundTrip(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		logLevel zerolog.Level
		err      error
		assert   func(t *testing.T, logs string)
	}{
		{
			uc:       "debug log level without error",
			logLevel: zerolog.DebugLevel,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Empty(t, logs)
			},
		},
		{
			uc:       "debug log level with error",
			logLevel: zerolog.DebugLevel,
			err:      errors.New("test error"),
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Empty(t, logs)
			},
		},
		{
			uc:       "trace log level without error",
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
				assert.Contains(t, line2["message"], "{ \"bar\": \"foo\" }")
			},
		},
		{
			uc:       "trace log level with error",
			logLevel: zerolog.TraceLevel,
			err:      errors.New("test error"),
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
				assert.Contains(t, line2["message"], "Failed sending request")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb}).Level(tc.logLevel)

			ctx := logger.WithContext(context.Background())

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://foo.bar?baz=foo", strings.NewReader("Foobar"))
			require.NoError(t, err)

			rawResponse := `HTTP/1.1 200 OK
Date: Thu, 24 Aug 2023 14:03:02 GMT
Content-Type: application/json
Content-Length: 16
X-Bar: Foo

{ "bar": "foo" }
`
			resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(rawResponse)), req)
			require.NoError(t, err)

			defer resp.Body.Close()

			rt := mocks.NewRoundTripperMock(t)
			rt.EXPECT().RoundTrip(req).Return(resp, tc.err)

			trt := NewTraceRoundTripper(rt)

			// WHEN
			result, err := trt.RoundTrip(req)

			// THEN
			if tc.err == nil {
				require.NoError(t, err)
				require.Equal(t, resp, result)
				result.Body.Close()
			} else {
				require.Error(t, err)
			}

			tc.assert(t, tb.CollectedLog())
		})
	}
}
