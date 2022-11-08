package httpcache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/cache/memory"
)

func TestRoundTripperRoundTrip(t *testing.T) {
	t.Parallel()

	var (
		setExpiresHeader bool
		requestCounts    int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCounts++

		if setExpiresHeader {
			w.Header().Set("Expires", time.Now().Add(20*time.Second).UTC().Format(http.TimeFormat))
		}

		_, err := w.Write([]byte("foobar"))
		require.NoError(t, err)
	}))

	defer srv.Close()

	for _, tc := range []struct {
		uc               string
		setExpiresHeader bool
		requestCounts    int
	}{
		{uc: "should cache response", setExpiresHeader: true, requestCounts: 1},
		{uc: "should not cache response", setExpiresHeader: false, requestCounts: 4},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			requestCounts = 0
			setExpiresHeader = tc.setExpiresHeader

			client := &http.Client{
				Transport: &RoundTripper{Transport: http.DefaultTransport},
			}

			ctx := cache.WithContext(context.Background(), memory.New())
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			for c := 0; c < 4; c++ {
				resp, err := client.Do(req)
				require.NoError(t, err)

				resp.Body.Close()
			}

			assert.Equal(t, tc.requestCounts, requestCounts)
		})
	}
}
