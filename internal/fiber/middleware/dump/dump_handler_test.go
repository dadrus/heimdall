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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDumpHandlerExecution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		logLevel zerolog.Level
		err      error
		assert   func(t *testing.T, logstring string)
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
				assert.Contains(t, line2["message"], "Barfoo")
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
				assert.Contains(t, line2["message"], "Failed processing request")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb}).Level(tc.logLevel)

			app := fiber.New()
			app.Use(
				func(c *fiber.Ctx) error {
					ctx := c.UserContext()

					c.SetUserContext(logger.WithContext(ctx))

					return c.Next()
				},
				New(),
			)
			app.Get("/test", func(ctx *fiber.Ctx) error {
				ctx.Write([]byte("Barfoo"))
				ctx.Status(http.StatusOK)

				return tc.err
			})

			req := httptest.NewRequest(http.MethodGet, "/test", strings.NewReader("Foobar"))

			// WHEN
			resp, err := app.Test(req)
			require.NoError(t, app.Shutdown())

			// THEN
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			tc.assert(t, tb.CollectedLog())
		})
	}
}
