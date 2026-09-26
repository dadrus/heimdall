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
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestTraceRoundTripperRoundTrip(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		logLevel zerolog.Level
		err      error
		assert   func(t *testing.T, logs string)
	}{
		"debug log level without error": {
			logLevel: zerolog.DebugLevel,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Empty(t, logs)
			},
		},
		"debug log level with error": {
			logLevel: zerolog.DebugLevel,
			err:      assert.AnError,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Empty(t, logs)
			},
		},
		"trace log level without error": {
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
		"trace log level with error": {
			logLevel: zerolog.TraceLevel,
			err:      assert.AnError,
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
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb}).Level(tc.logLevel)

			ctx := logger.WithContext(t.Context())

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

			rt := NewRoundTripperMock(t)
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

func TestTraceRoundTripperDoesNotMaterializeStreamingRequestBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentLength int64
		contentType   string
		upgrade       string
	}{
		"unknown length": {contentLength: -1, contentType: "application/json"},
		"native grpc":    {contentLength: 6, contentType: "application/grpc"},
		"sse":            {contentLength: 6, contentType: "text/event-stream"},
		"upgrade":        {contentLength: 6, contentType: "application/json", upgrade: "websocket"},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			body := &trackingReadCloser{Reader: strings.NewReader("Foobar")}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://foo.bar", body)
			require.NoError(t, err)
			req.ContentLength = tc.contentLength
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set("Upgrade", tc.upgrade)

			logger := zerolog.New(io.Discard).Level(zerolog.TraceLevel)
			req = req.WithContext(logger.WithContext(req.Context()))

			trt := NewTraceRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
				assert.False(t, body.read)

				return &http.Response{ //nolint:bodyclose
					StatusCode:    http.StatusNoContent,
					Status:        "204 No Content",
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        make(http.Header),
					Body:          http.NoBody,
					ContentLength: 0,
					Request:       req,
				}, nil
			}))

			resp, err := trt.RoundTrip(req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.False(t, body.read)
			require.NoError(t, resp.Body.Close())
		})
	}
}

func TestTraceRoundTripperDoesNotMaterializeStreamingResponseBody(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contentLength int64
		contentType   string
		statusCode    int
	}{
		"unknown length":      {contentLength: -1, contentType: "application/json", statusCode: http.StatusOK},
		"native grpc":         {contentLength: 6, contentType: "application/grpc", statusCode: http.StatusOK},
		"sse":                 {contentLength: 6, contentType: "text/event-stream", statusCode: http.StatusOK},
		"switching protocols": {contentLength: 6, contentType: "application/json", statusCode: http.StatusSwitchingProtocols},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			logger := zerolog.New(io.Discard).Level(zerolog.TraceLevel)
			req, err := http.NewRequestWithContext(
				logger.WithContext(t.Context()),
				http.MethodGet,
				"https://foo.bar",
				nil,
			)
			require.NoError(t, err)

			body := &trackingReadCloser{Reader: strings.NewReader("Foobar")}
			resp := &http.Response{ //nolint:bodyclose
				StatusCode:    tc.statusCode,
				Status:        fmt.Sprintf("%d %s", tc.statusCode, http.StatusText(tc.statusCode)),
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				Body:          body,
				ContentLength: tc.contentLength,
				Request:       req,
			}
			resp.Header.Set("Content-Type", tc.contentType)

			trt := NewTraceRoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return resp, nil
			}))

			result, err := trt.RoundTrip(req)
			require.NoError(t, err)
			require.Same(t, resp, result)
			assert.False(t, body.read)
			require.NoError(t, result.Body.Close())
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type trackingReadCloser struct {
	io.Reader

	read bool
}

func (r *trackingReadCloser) Read(data []byte) (int, error) {
	r.read = true

	return r.Reader.Read(data)
}

func (*trackingReadCloser) Close() error { return nil }
