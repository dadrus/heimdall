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

package logger

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestHandlerExecution(t *testing.T) {
	// GIVEN
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))

	parentCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	})

	for _, tc := range []struct {
		uc        string
		setHeader func(t *testing.T, req *http.Request)
		assert    func(t *testing.T, logstring string)
	}{
		{
			uc:        "without tracing",
			setHeader: func(t *testing.T, _ *http.Request) { t.Helper() },
			assert: func(t *testing.T, logstring string) {
				t.Helper()

				assert.Contains(t, logstring, "test called")
				assert.Contains(t, logstring, "_span_id")
				assert.Contains(t, logstring, "_trace_id")
				assert.NotContains(t, logstring, "_parent_id")

				var logData map[string]string
				require.NoError(t, json.Unmarshal([]byte(logstring), &logData))
				assert.NotEqual(t, parentCtx.TraceID().String(), logData["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logData["_parent_id"])
			},
		},
		{
			uc: "with tracing",
			setHeader: func(t *testing.T, req *http.Request) {
				t.Helper()

				otel.GetTextMapPropagator().Inject(
					trace.ContextWithRemoteSpanContext(req.Context(), parentCtx),
					propagation.HeaderCarrier(req.Header))
			},
			assert: func(t *testing.T, logstring string) {
				t.Helper()

				assert.Contains(t, logstring, "test called")
				assert.Contains(t, logstring, "_span_id")
				assert.Contains(t, logstring, "_trace_id")
				assert.Contains(t, logstring, "_parent_id")

				var logData map[string]string
				require.NoError(t, json.Unmarshal([]byte(logstring), &logData))
				assert.Equal(t, parentCtx.TraceID().String(), logData["_trace_id"])
				assert.Equal(t, parentCtx.SpanID().String(), logData["_parent_id"])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			srv := httptest.NewServer(
				alice.New(
					func(next http.Handler) http.Handler {
						return otelhttp.NewHandler(
							next,
							"",
							otelhttp.WithTracerProvider(otel.GetTracerProvider()),
							otelhttp.WithServerName("proxy"),
							otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
								return fmt.Sprintf("EntryPoint %s %s%s",
									strings.ToLower(req.URL.Scheme), "ctx.Context().LocalAddr().String()", req.URL.Path)
							}),
						)
					},
					New(logger),
				).ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
					zerolog.Ctx(req.Context()).Info().Msg("test called")

					rw.WriteHeader(http.StatusOK)
				}),
			)

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				srv.URL+"/test",
				nil,
			)
			require.NoError(t, err)

			tc.setHeader(t, req)

			// WHEN
			resp, err := srv.Client().Do(req)

			// THEN
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			tc.assert(t, tb.CollectedLog())
		})
	}
}
