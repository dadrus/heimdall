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
	"errors"
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

	"github.com/dadrus/heimdall/internal/accesscontext"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestHandlerExecution(t *testing.T) {
	// GIVEN
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))

	parentCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	})

	for uc, tc := range map[string]struct {
		method        string
		setHeader     func(t *testing.T, req *http.Request)
		handleRequest func(t *testing.T, rw http.ResponseWriter, req *http.Request)
		assert        func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2, logEvent3 map[string]any)
	}{
		"without tracing, x-* header and errors": {
			method:    http.MethodGet,
			setHeader: func(t *testing.T, _ *http.Request) { t.Helper() },
			handleRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				accesscontext.SetSubject(req.Context(), "foo")
				rw.WriteHeader(http.StatusOK)
			},
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2, logEvent3 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 11)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Contains(t, logEvent1, "_http_user_agent")
				assert.Equal(t, clientReq.Method, logEvent1["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent1["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent1["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent1["_http_scheme"])
				assert.Contains(t, logEvent1, "_trace_id")
				assert.Contains(t, logEvent1, "_trace_id")
				assert.NotEqual(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 4)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_span_id")
				assert.NotContains(t, logEvent2, "_parent_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_span_id"], logEvent2["_span_id"])
				assert.Equal(t, "test called", logEvent2["message"])

				require.Len(t, logEvent3, 16)
				assert.Equal(t, "info", logEvent3["level"])
				assert.Contains(t, logEvent3, "_tx_start")
				assert.Contains(t, logEvent3, "_tx_duration_ms")
				assert.Contains(t, logEvent3, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent3["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent3["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent3["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent3["_http_scheme"])
				assert.Contains(t, logEvent3, "_trace_id")
				assert.Contains(t, logEvent3, "_span_id")
				assert.NotContains(t, logEvent3, "_parent_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent3["_trace_id"])
				assert.Equal(t, logEvent1["_span_id"], logEvent3["_span_id"])
				assert.Contains(t, logEvent3, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusOK), logEvent3["_http_status_code"], 0.001)
				assert.Equal(t, true, logEvent3["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "foo", logEvent3["_subject"])
				assert.Contains(t, logEvent3, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent3["message"])
			},
		},
		"with tracing, x-* header and error": {
			method: http.MethodPost,
			setHeader: func(t *testing.T, req *http.Request) {
				t.Helper()

				otel.GetTextMapPropagator().Inject(
					trace.ContextWithRemoteSpanContext(req.Context(), parentCtx),
					propagation.HeaderCarrier(req.Header))

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "foobar.com")
				req.Header.Set("X-Forwarded-Path", "/baz")
				req.Header.Set("X-Forwarded-Uri", "https://foobar.com/bar")
				req.Header.Set("X-Forwarded-For", "127.0.0.1")
				req.Header.Set("Forwarded", "for=127.0.0.1")
			},
			handleRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				accesscontext.SetError(req.Context(), errors.New("test error"))
				rw.WriteHeader(http.StatusInternalServerError)
			},
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2, logEvent3 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 17)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Contains(t, logEvent1, "_http_user_agent")
				assert.Equal(t, clientReq.Method, logEvent1["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent1["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent1["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent1["_http_scheme"])
				assert.Contains(t, logEvent1, "_span_id")
				assert.Equal(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.Equal(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])
				assert.Equal(t, "https", logEvent1["_http_x_forwarded_proto"])
				assert.Equal(t, "foobar.com", logEvent1["_http_x_forwarded_host"])
				assert.Equal(t, "https://foobar.com/bar", logEvent1["_http_x_forwarded_uri"])
				assert.Equal(t, "127.0.0.1", logEvent1["_http_x_forwarded_for"])
				assert.Equal(t, "for=127.0.0.1", logEvent1["_http_forwarded"])

				require.Len(t, logEvent2, 5)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_span_id")
				assert.Contains(t, logEvent2, "_parent_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_span_id"], logEvent2["_span_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent2["_parent_id"])
				assert.Equal(t, "test called", logEvent2["message"])

				require.Len(t, logEvent3, 22)
				assert.Equal(t, "info", logEvent3["level"])
				assert.Contains(t, logEvent3, "_tx_start")
				assert.Contains(t, logEvent3, "_tx_duration_ms")
				assert.Contains(t, logEvent3, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent3["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent3["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent3["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent3["_http_scheme"])
				assert.Equal(t, logEvent1["_trace_id"], logEvent3["_trace_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent3["_parent_id"])
				assert.Equal(t, logEvent1["_span_id"], logEvent3["_span_id"])
				assert.Contains(t, logEvent3, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusInternalServerError), logEvent3["_http_status_code"], 0.001)
				assert.Equal(t, false, logEvent3["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "test error", logEvent3["error"])
				assert.Contains(t, logEvent3, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent3["message"])
				assert.Equal(t, "https", logEvent3["_http_x_forwarded_proto"])
				assert.Equal(t, "foobar.com", logEvent3["_http_x_forwarded_host"])
				assert.Equal(t, "https://foobar.com/bar", logEvent3["_http_x_forwarded_uri"])
				assert.Equal(t, "127.0.0.1", logEvent3["_http_x_forwarded_for"])
				assert.Equal(t, "for=127.0.0.1", logEvent3["_http_forwarded"])
			},
		},
		"without tracing and x-* header, but with subject and error set on context": {
			method:    http.MethodPatch,
			setHeader: func(t *testing.T, _ *http.Request) { t.Helper() },
			handleRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				accesscontext.SetSubject(req.Context(), "bar")
				accesscontext.SetError(req.Context(), errors.New("test error"))
				rw.WriteHeader(http.StatusUnauthorized)
			},
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2, logEvent3 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 11)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Contains(t, logEvent1, "_http_user_agent")
				assert.Equal(t, clientReq.Method, logEvent1["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent1["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent1["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent1["_http_scheme"])
				assert.Contains(t, logEvent1, "_trace_id")
				assert.Contains(t, logEvent1, "_trace_id")
				assert.NotEqual(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 4)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_span_id")
				assert.NotContains(t, logEvent2, "_parent_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_span_id"], logEvent2["_span_id"])
				assert.Equal(t, "test called", logEvent2["message"])

				require.Len(t, logEvent3, 17)
				assert.Equal(t, "info", logEvent3["level"])
				assert.Contains(t, logEvent3, "_tx_start")
				assert.Contains(t, logEvent3, "_tx_duration_ms")
				assert.Contains(t, logEvent3, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent3["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent3["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent3["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent3["_http_scheme"])
				assert.Contains(t, logEvent3, "_trace_id")
				assert.Contains(t, logEvent3, "_trace_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent3["_trace_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent3["_parent_id"])
				assert.Contains(t, logEvent3, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusUnauthorized), logEvent3["_http_status_code"], 0.001)
				assert.Equal(t, false, logEvent3["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "bar", logEvent3["_subject"])
				assert.Equal(t, "test error", logEvent3["error"])
				assert.Contains(t, logEvent3, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent3["message"])
			},
		},
		"without tracing and x-* header, but with subject and redirect handling": {
			method:    http.MethodPatch,
			setHeader: func(t *testing.T, _ *http.Request) { t.Helper() },
			handleRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				accesscontext.SetSubject(req.Context(), "bar")
				rw.WriteHeader(http.StatusSeeOther)
			},
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2, logEvent3 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 11)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Contains(t, logEvent1, "_http_user_agent")
				assert.Equal(t, clientReq.Method, logEvent1["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent1["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent1["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent1["_http_scheme"])
				assert.Contains(t, logEvent1, "_trace_id")
				assert.Contains(t, logEvent1, "_trace_id")
				assert.NotEqual(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.NotEqual(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])

				require.Len(t, logEvent2, 4)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_span_id")
				assert.NotContains(t, logEvent2, "_parent_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_span_id"], logEvent2["_span_id"])
				assert.Equal(t, "test called", logEvent2["message"])

				require.Len(t, logEvent3, 16)
				assert.Equal(t, "info", logEvent3["level"])
				assert.Contains(t, logEvent3, "_tx_start")
				assert.Contains(t, logEvent3, "_tx_duration_ms")
				assert.Contains(t, logEvent3, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent3["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent3["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent3["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent3["_http_scheme"])
				assert.Contains(t, logEvent3, "_trace_id")
				assert.Contains(t, logEvent3, "_trace_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent3["_trace_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent3["_parent_id"])
				assert.Contains(t, logEvent3, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusSeeOther), logEvent3["_http_status_code"], 0.001)
				assert.Equal(t, false, logEvent3["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "bar", logEvent3["_subject"])
				assert.Contains(t, logEvent3, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent3["message"])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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
								return "EntryPoint " + strings.ToLower(req.URL.Scheme) + " " +
									httpx.LocalAddress(req) + req.URL.Path
							}),
						)
					},
					New(logger, WithAccessStatusEnabled(true)),
				).ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
					zerolog.Ctx(req.Context()).Info().Msg("test called")

					tc.handleRequest(t, rw, req)
				}),
			)

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				t.Context(),
				tc.method,
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

			events := strings.Split(tb.CollectedLog(), "}")
			require.Len(t, events, 4)

			var (
				logLine1 map[string]any
				logLine2 map[string]any
				logLine3 map[string]any
			)

			require.NoError(t, json.Unmarshal([]byte(events[0]+"}"), &logLine1))
			require.NoError(t, json.Unmarshal([]byte(events[1]+"}"), &logLine2))
			require.NoError(t, json.Unmarshal([]byte(events[2]+"}"), &logLine3))

			tc.assert(t, req, logLine1, logLine2, logLine3)
		})
	}
}
