// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/dadrus/heimdall/internal/accesscontext"
	tracingmiddleware "github.com/dadrus/heimdall/internal/fiber/middleware/opentelemetry"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestLoggerHandler(t *testing.T) {
	// GIVEN
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}))

	parentCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	})

	for _, tc := range []struct {
		uc               string
		setHeader        func(t *testing.T, req *http.Request)
		configureHandler func(t *testing.T, ctx *fiber.Ctx) error
		assert           func(t *testing.T, logEvent1, logEvent2 map[string]any)
	}{
		{
			uc:        "without tracing, x-* header and errors",
			setHeader: func(t *testing.T, req *http.Request) { t.Helper() },
			configureHandler: func(t *testing.T, ctx *fiber.Ctx) error {
				t.Helper()

				accesscontext.SetSubject(ctx.UserContext(), "foo")

				return nil
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 11)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Contains(t, logEvent1, "_http_user_agent")
				assert.Equal(t, "GET", logEvent1["_http_method"])
				assert.Equal(t, "example.com", logEvent1["_http_host"])
				assert.Equal(t, "/test", logEvent1["_http_path"])
				assert.Equal(t, "http", logEvent1["_http_scheme"])
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
				assert.Equal(t, "GET", logEvent2["_http_method"])
				assert.Equal(t, "example.com", logEvent2["_http_host"])
				assert.Equal(t, "/test", logEvent2["_http_path"])
				assert.Equal(t, "http", logEvent2["_http_scheme"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Equal(t, logEvent2["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent2["_parent_id"], logEvent2["_parent_id"])
				assert.Contains(t, logEvent2, "_body_bytes_sent")
				assert.Equal(t, float64(200), logEvent2["_http_status_code"])
				assert.Equal(t, true, logEvent2["_access_granted"])
				assert.Equal(t, "foo", logEvent2["_subject"])
				assert.Contains(t, logEvent2, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent2["message"])
			},
		},
		{
			uc: "with tracing, x-* header and error",
			setHeader: func(t *testing.T, req *http.Request) {
				t.Helper()

				// nolint: contextcheck
				otel.GetTextMapPropagator().Inject(
					trace.ContextWithRemoteSpanContext(context.Background(), parentCtx),
					propagation.HeaderCarrier(req.Header))

				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("X-Forwarded-Host", "foobar.com")
				req.Header.Set("X-Forwarded-Path", "/bar")
				req.Header.Set("X-Forwarded-Uri", "https://foobar.com/bar")
				req.Header.Set("X-Forwarded-For", "127.0.0.1")
				req.Header.Set("Forwarded", "for=127.0.0.1")
			},
			configureHandler: func(t *testing.T, ctx *fiber.Ctx) error {
				t.Helper()

				return fmt.Errorf("test error") // nolint: goerr113
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 18)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Contains(t, logEvent1, "_http_user_agent")
				assert.Equal(t, "GET", logEvent1["_http_method"])
				assert.Equal(t, "example.com", logEvent1["_http_host"])
				assert.Equal(t, "/test", logEvent1["_http_path"])
				assert.Equal(t, "http", logEvent1["_http_scheme"])
				assert.Contains(t, logEvent1, "_span_id")
				assert.Equal(t, parentCtx.TraceID().String(), logEvent1["_trace_id"])
				assert.Equal(t, parentCtx.SpanID().String(), logEvent1["_parent_id"])
				assert.Equal(t, "TX started", logEvent1["message"])
				assert.Equal(t, "https", logEvent1["_http_x_forwarded_proto"])
				assert.Equal(t, "foobar.com", logEvent1["_http_x_forwarded_host"])
				assert.Equal(t, "/bar", logEvent1["_http_x_forwarded_path"])
				assert.Equal(t, "https://foobar.com/bar", logEvent1["_http_x_forwarded_uri"])
				assert.Equal(t, "127.0.0.1", logEvent1["_http_x_forwarded_for"])
				assert.Equal(t, "for=127.0.0.1", logEvent1["_http_forwarded"])

				require.Len(t, logEvent2, 23)
				assert.Equal(t, "info", logEvent2["level"])
				assert.Contains(t, logEvent2, "_tx_start")
				assert.Contains(t, logEvent2, "_tx_duration_ms")
				assert.Contains(t, logEvent2, "_client_ip")
				assert.Equal(t, "GET", logEvent2["_http_method"])
				assert.Equal(t, "example.com", logEvent2["_http_host"])
				assert.Equal(t, "/test", logEvent2["_http_path"])
				assert.Equal(t, "http", logEvent2["_http_scheme"])
				assert.Equal(t, logEvent2["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent2["_parent_id"], logEvent2["_parent_id"])
				assert.Equal(t, logEvent2["_span_id"], logEvent2["_span_id"])
				assert.Contains(t, logEvent2, "_body_bytes_sent")
				assert.Equal(t, float64(200), logEvent2["_http_status_code"])
				assert.Equal(t, false, logEvent2["_access_granted"])
				assert.Equal(t, "test error", logEvent2["error"])
				assert.Contains(t, logEvent2, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent2["message"])
				assert.Equal(t, "https", logEvent1["_http_x_forwarded_proto"])
				assert.Equal(t, "foobar.com", logEvent1["_http_x_forwarded_host"])
				assert.Equal(t, "/bar", logEvent1["_http_x_forwarded_path"])
				assert.Equal(t, "https://foobar.com/bar", logEvent1["_http_x_forwarded_uri"])
				assert.Equal(t, "127.0.0.1", logEvent1["_http_x_forwarded_for"])
				assert.Equal(t, "for=127.0.0.1", logEvent1["_http_forwarded"])
			},
		},
		{
			uc:        "without tracing and x-* header, but with subject and error set on context",
			setHeader: func(t *testing.T, req *http.Request) { t.Helper() },
			configureHandler: func(t *testing.T, ctx *fiber.Ctx) error {
				t.Helper()

				accesscontext.SetSubject(ctx.UserContext(), "bar")
				accesscontext.SetError(ctx.UserContext(), fmt.Errorf("test error")) // nolint: goerr113

				return nil
			},
			assert: func(t *testing.T, logEvent1, logEvent2 map[string]any) {
				t.Helper()

				require.Len(t, logEvent1, 11)
				assert.Equal(t, "info", logEvent1["level"])
				assert.Contains(t, logEvent1, "_tx_start")
				assert.Contains(t, logEvent1, "_client_ip")
				assert.Contains(t, logEvent1, "_http_user_agent")
				assert.Equal(t, "GET", logEvent1["_http_method"])
				assert.Equal(t, "example.com", logEvent1["_http_host"])
				assert.Equal(t, "/test", logEvent1["_http_path"])
				assert.Equal(t, "http", logEvent1["_http_scheme"])
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
				assert.Equal(t, "GET", logEvent2["_http_method"])
				assert.Equal(t, "example.com", logEvent2["_http_host"])
				assert.Equal(t, "/test", logEvent2["_http_path"])
				assert.Equal(t, "http", logEvent2["_http_scheme"])
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Contains(t, logEvent2, "_trace_id")
				assert.Equal(t, logEvent2["_trace_id"], logEvent2["_trace_id"])
				assert.Equal(t, logEvent2["_parent_id"], logEvent2["_parent_id"])
				assert.Contains(t, logEvent2, "_body_bytes_sent")
				assert.Equal(t, float64(200), logEvent2["_http_status_code"])
				assert.Equal(t, false, logEvent2["_access_granted"])
				assert.Equal(t, "bar", logEvent2["_subject"])
				assert.Equal(t, "test error", logEvent2["error"])
				assert.Contains(t, logEvent2, "_http_user_agent")
				assert.Equal(t, "TX finished", logEvent2["message"])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})

			app := fiber.New()
			app.Use(tracingmiddleware.New())
			app.Use(New(logger))
			app.Get("/test", func(ctx *fiber.Ctx) error { return tc.configureHandler(t, ctx) })

			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			tc.setHeader(t, req)

			// WHEN
			resp, err := app.Test(req, 1000000)
			require.NoError(t, app.Shutdown())

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

			tc.assert(t, logLine1, logLine2)
		})
	}
}
