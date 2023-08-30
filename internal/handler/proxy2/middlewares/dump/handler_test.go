package dump

import (
	"context"
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

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestDumpHandlerExecution(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		logLevel zerolog.Level
		assert   func(t *testing.T, logstring string)
	}{
		{
			uc:       "debug log level",
			logLevel: zerolog.DebugLevel,
			assert: func(t *testing.T, logs string) {
				t.Helper()

				assert.Empty(t, logs)
			},
		},
		{
			uc:       "trace log level",
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
		t.Run(tc.uc, func(t *testing.T) {
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
				).ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
					rw.WriteHeader(http.StatusOK)
					rw.Write([]byte("Barfoo"))
				}))

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				fmt.Sprintf("%s/test", srv.URL),
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
