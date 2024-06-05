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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCounts++

		if setExpiresHeader {
			w.Header().Set("Expires", time.Now().Add(20*time.Second).UTC().Format(http.TimeFormat))
		}

		_, err := w.Write([]byte("foobar"))
		assert.NoError(t, err)
	}))

	defer srv.Close()

	for _, tc := range []struct {
		uc               string
		setExpiresHeader bool
		defaultTTL       time.Duration
		requestCounts    int
	}{
		{uc: "should cache response with expires header set", setExpiresHeader: true, requestCounts: 1},
		{uc: "should not cache response without default cache ttl", requestCounts: 4},
		{uc: "should cache response with default cache ttl without other headers", defaultTTL: 10 * time.Second, requestCounts: 1},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			requestCounts = 0
			setExpiresHeader = tc.setExpiresHeader

			client := &http.Client{
				Transport: &RoundTripper{
					Transport:       http.DefaultTransport,
					DefaultCacheTTL: tc.defaultTTL,
				},
			}

			cch, err := memory.NewCache(nil, nil)
			require.NoError(t, err)

			ctx := cache.WithContext(context.Background(), cch)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			for range 4 {
				resp, err := client.Do(req)
				require.NoError(t, err)

				resp.Body.Close()
			}

			assert.Equal(t, tc.requestCounts, requestCounts)
		})
	}
}
