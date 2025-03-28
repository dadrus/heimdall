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

package accesslog

import (
	"errors"
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

	"github.com/dadrus/heimdall/internal/accesscontext"
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
		assert        func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2 map[string]any)
	}{
		"without tracing, x-* header and errors": {
			method:    http.MethodGet,
			setHeader: func(t *testing.T, _ *http.Request) { t.Helper() },
			handleRequest: func(t *testing.T, rw http.ResponseWriter, req *http.Request) {
				t.Helper()

				accesscontext.SetSubject(req.Context(), "foo")
				rw.WriteHeader(http.StatusOK)
			},
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2 map[string]any) {
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

				require.Len(t, logEvent2, 16)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent2["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent2["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent2["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent2["_http_scheme"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent2["_parent_id"])
				assert.Contains(t, logEvent2, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusOK), logEvent2["_http_status_code"], 0.001)
				assert.Equal(t, true, logEvent2["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "foo", logEvent2["_subject"])
				assert.Contains(t, logEvent2, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent2["message"])
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
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2 map[string]any) {
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

				require.Len(t, logEvent2, 22)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent2["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent2["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent2["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent2["_http_scheme"])
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent2["_parent_id"])
				assert.Equal(t, logEvent1["_span_id"], logEvent2["_span_id"])
				assert.Contains(t, logEvent2, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusInternalServerError), logEvent2["_http_status_code"], 0.001)
				assert.Equal(t, false, logEvent2["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "test error", logEvent2["error"])
				assert.Contains(t, logEvent2, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent2["message"])
				assert.Equal(t, "https", logEvent1["_http_x_forwarded_proto"])
				assert.Equal(t, "foobar.com", logEvent1["_http_x_forwarded_host"])
				assert.Equal(t, "https://foobar.com/bar", logEvent1["_http_x_forwarded_uri"])
				assert.Equal(t, "127.0.0.1", logEvent1["_http_x_forwarded_for"])
				assert.Equal(t, "for=127.0.0.1", logEvent1["_http_forwarded"])
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
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2 map[string]any) {
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

				require.Len(t, logEvent2, 17)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent2["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent2["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent2["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent2["_http_scheme"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent2["_parent_id"])
				assert.Contains(t, logEvent2, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusUnauthorized), logEvent2["_http_status_code"], 0.001)
				assert.Equal(t, false, logEvent2["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "bar", logEvent2["_subject"])
				assert.Equal(t, "test error", logEvent2["error"])
				assert.Contains(t, logEvent2, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent2["message"])
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
			assert: func(t *testing.T, clientReq *http.Request, logEvent1, logEvent2 map[string]any) {
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

				require.Len(t, logEvent2, 16)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, clientReq.Method, logEvent2["_http_method"])
				assert.Equal(t, clientReq.URL.Host, logEvent2["_http_host"])
				assert.Equal(t, clientReq.URL.Path, logEvent2["_http_path"])
				assert.Equal(t, clientReq.URL.Scheme, logEvent2["_http_scheme"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Equal(t, logEvent1["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent1["_parent_id"], logEvent2["_parent_id"])
				assert.Contains(t, logEvent2, "_body_bytes_sent")
				assert.InDelta(t, float64(http.StatusSeeOther), logEvent2["_http_status_code"], 0.001)
				assert.Equal(t, false, logEvent2["_access_granted"]) //nolint:testifylint
				assert.Equal(t, "bar", logEvent2["_subject"])
				assert.Contains(t, logEvent2, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent2["message"])
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
								return fmt.Sprintf("EntryPoint %s %s%s",
									strings.ToLower(req.URL.Scheme), "ctx.Context().LocalAddr().String()", req.URL.Path)
							}),
						)
					},
					New(logger),
				).ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
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
			require.Len(t, events, 3)

			var (
				logLine1 map[string]any
				logLine2 map[string]any
			)

			require.NoError(t, json.Unmarshal([]byte(events[0]+"}"), &logLine1))
			require.NoError(t, json.Unmarshal([]byte(events[1]+"}"), &logLine2))

			tc.assert(t, req, logLine1, logLine2)
		})
	}
}
