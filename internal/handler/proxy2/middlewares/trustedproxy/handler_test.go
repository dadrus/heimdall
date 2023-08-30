package trustedproxy

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/justinas/alice"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

func TestHeaderFiltering(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc         string
		ips        []string
		shouldDrop bool
	}{
		{"bad IP range", []string{"/128"}, true},
		{"single IP trusted", []string{"127.0.0.1"}, false},
		{"trusted IP range", []string{"127.0.0.0/24"}, false},
		{"source not in IP range", []string{"172.0.0.0/24"}, true},
		{"empty list", []string{}, true},
	} {
		t.Run(tc.uc, func(t *testing.T) {
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

			srv := httptest.NewServer(
				alice.New(New(log.Logger, tc.ips...)).
					ThenFunc(func(rw http.ResponseWriter, req *http.Request) {
						received = maps.Clone(req.Header)

						rw.WriteHeader(http.StatusGone)
					}))

			defer srv.Close()

			req, err := http.NewRequestWithContext(
				context.Background(), http.MethodGet, fmt.Sprintf("%s/test", srv.URL), nil)
			req.Header = send
			require.NoError(t, err)

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
		})
	}
}
