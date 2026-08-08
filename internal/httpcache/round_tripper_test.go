// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	cachemocks "github.com/dadrus/heimdall/internal/cache/mocks"
)

func TestRoundTripperRoundTrip(t *testing.T) {
	t.Parallel()

	type requestSpec struct {
		method  string
		path    string
		headers http.Header
		body    string
	}

	type responseBodyFunc func(req *http.Request, requestBody string, originHit int32) string

	cacheableHeaders := func() http.Header {
		return http.Header{
			"Cache-Control": {"max-age=60"},
		}
	}

	for uc, tc := range map[string]struct {
		fallbackCacheTTL       time.Duration
		uncacheableVaryHeaders []string
		responseStatus         int
		responseHeaders        http.Header
		responseBody           responseBodyFunc
		requests               []requestSpec
		expectedOriginHits     int32
		expectedBodies         []string
	}{
		"should cache response with expires header set": {
			responseHeaders: http.Header{
				"Expires": {time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 1,
			expectedBodies: []string{
				"origin-hit-1",
				"origin-hit-1",
				"origin-hit-1",
				"origin-hit-1",
			},
		},
		"should not cache response without fallback cache ttl": {
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 4,
			expectedBodies: []string{
				"origin-hit-1",
				"origin-hit-2",
				"origin-hit-3",
				"origin-hit-4",
			},
		},
		"should cache response using fallback cache ttl": {
			fallbackCacheTTL: 10 * time.Second,
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 1,
			expectedBodies: []string{
				"origin-hit-1",
				"origin-hit-1",
				"origin-hit-1",
				"origin-hit-1",
			},
		},
		"should cache response with max age": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 1,
			expectedBodies: []string{
				"origin-hit-1",
				"origin-hit-1",
				"origin-hit-1",
				"origin-hit-1",
			},
		},
		"should not cache private response in shared cache": {
			responseHeaders: http.Header{
				"Cache-Control": {"private, max-age=60"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not cache response with no-store directive": {
			responseHeaders: http.Header{
				"Cache-Control": {"no-store, max-age=60"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not cache response when request contains no-store directive": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cache-Control": {"no-store"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cache-Control": {"no-store"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not reuse response with no-cache directive without revalidation": {
			responseHeaders: http.Header{
				"Cache-Control": {"no-cache, max-age=60"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should honor request no-cache directive": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cache-Control": {"no-cache"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should honor request max-age directive by bypassing lookup": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cache-Control": {"max-age=0"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should honor request min-fresh directive by bypassing lookup": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cache-Control": {"min-fresh=30"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not cache response with non-cacheable status code": {
			fallbackCacheTTL: 10 * time.Second,
			responseStatus:   http.StatusInternalServerError,
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not cache response containing set-cookie": {
			responseHeaders: http.Header{
				"Cache-Control": {"public, max-age=60"},
				"Set-Cookie":    {"session=alice; Path=/; HttpOnly"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should separate responses by request url": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(req *http.Request, _ string, _ int32) string {
				return req.URL.Path
			},
			requests: []requestSpec{
				{method: http.MethodGet, path: "/alice"},
				{method: http.MethodGet, path: "/bob"},
				{method: http.MethodGet, path: "/alice"},
				{method: http.MethodGet, path: "/bob"},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"/alice", "/bob", "/alice", "/bob"},
		},
		"should separate responses by request method": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(req *http.Request, _ string, _ int32) string {
				return req.Method
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodHead},
				{method: http.MethodGet},
				{method: http.MethodHead},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{http.MethodGet, "", http.MethodGet, ""},
		},
		"should not cache authenticated response without explicit permission": {
			responseHeaders: http.Header{
				"Cache-Control": {"max-age=60"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer alice"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer alice"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should separate explicitly public authenticated responses without vary authorization": {
			responseHeaders: http.Header{
				"Cache-Control": {"public, max-age=60"},
			},
			responseBody: func(req *http.Request, _ string, _ int32) string {
				return req.Header.Get("Authorization")
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer alice"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer bob"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer alice"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer bob"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies: []string{
				"Bearer alice",
				"Bearer bob",
				"Bearer alice",
				"Bearer bob",
			},
		},
		"should separate public authenticated responses when varying by authorization": {
			responseHeaders: http.Header{
				"Cache-Control": {"public, max-age=60"},
				"Vary":          {"Authorization"},
			},
			responseBody: func(req *http.Request, _ string, _ int32) string {
				return req.Header.Get("Authorization")
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer alice"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer bob"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer alice"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Authorization": {"Bearer bob"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies: []string{
				"Bearer alice",
				"Bearer bob",
				"Bearer alice",
				"Bearer bob",
			},
		},
		"should separate responses by vary cookie": {
			responseHeaders: http.Header{
				"Cache-Control": {"max-age=60"},
				"Vary":          {"Cookie"},
			},
			responseBody: func(req *http.Request, _ string, _ int32) string {
				return req.Header.Get("Cookie")
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cookie": {"session=alice"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cookie": {"session=bob"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cookie": {"session=alice"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Cookie": {"session=bob"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies: []string{
				"session=alice",
				"session=bob",
				"session=alice",
				"session=bob",
			},
		},
		"should separate responses by vary custom header": {
			responseHeaders: http.Header{
				"Cache-Control": {"max-age=60"},
				"Vary":          {"X-Tenant"},
			},
			responseBody: func(req *http.Request, _ string, _ int32) string {
				return req.Header.Get("X-Tenant")
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"X-Tenant": {"tenant-a"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"X-Tenant": {"tenant-b"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"X-Tenant": {"tenant-a"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"X-Tenant": {"tenant-b"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies: []string{
				"tenant-a",
				"tenant-b",
				"tenant-a",
				"tenant-b",
			},
		},
		"should not cache response with vary wildcard": {
			responseHeaders: http.Header{
				"Cache-Control": {"max-age=60"},
				"Vary":          {"*"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{method: http.MethodGet},
				{method: http.MethodGet},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not cache response varying by configured uncacheable header": {
			uncacheableVaryHeaders: []string{" signature "},
			responseHeaders: http.Header{
				"Cache-Control": {"max-age=60"},
				"Vary":          {"Signature"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"Signature": {"sig-a"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Signature": {"sig-a"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not cache response varying by connection-specific header": {
			responseHeaders: http.Header{
				"Cache-Control": {"max-age=60"},
				"Vary":          {"X-Hop"},
			},
			responseBody: func(_ *http.Request, _ string, originHit int32) string {
				return fmt.Sprintf("origin-hit-%d", originHit)
			},
			requests: []requestSpec{
				{
					method: http.MethodGet,
					headers: http.Header{
						"Connection": {"X-Hop"},
						"X-Hop":      {"hop-a"},
					},
				},
				{
					method: http.MethodGet,
					headers: http.Header{
						"Connection": {"X-Hop"},
						"X-Hop":      {"hop-a"},
					},
				},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"origin-hit-1", "origin-hit-2"},
		},
		"should not reuse cacheable post response for a different request body": {
			responseHeaders: cacheableHeaders(),
			responseBody: func(_ *http.Request, requestBody string, _ int32) string {
				return requestBody
			},
			requests: []requestSpec{
				{method: http.MethodPost, body: "token=alice"},
				{method: http.MethodPost, body: "token=bob"},
			},
			expectedOriginHits: 2,
			expectedBodies:     []string{"token=alice", "token=bob"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			var originHits atomic.Int32

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				originHit := originHits.Add(1)

				requestBody, err := io.ReadAll(req.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)

					return
				}

				for name, values := range tc.responseHeaders {
					for _, value := range values {
						w.Header().Add(name, value)
					}
				}

				status := tc.responseStatus
				if status == 0 {
					status = http.StatusOK
				}

				w.WriteHeader(status)

				responseBody := "foobar"
				if tc.responseBody != nil {
					responseBody = tc.responseBody(req, string(requestBody), originHit)
				}

				_, _ = io.WriteString(w, responseBody)
			}))
			t.Cleanup(srv.Close)

			cch := newStatefulCacheMock(t)

			client := &http.Client{
				Transport: &RoundTripper{
					Transport:              http.DefaultTransport,
					DefaultCacheTTL:        tc.fallbackCacheTTL,
					UncacheableVaryHeaders: tc.uncacheableVaryHeaders,
				},
			}

			actualBodies := make([]string, 0, len(tc.requests))
			ctx := cache.WithContext(t.Context(), cch)

			for _, request := range tc.requests {
				var body io.Reader
				if request.body != "" {
					body = strings.NewReader(request.body)
				}

				req, err := http.NewRequestWithContext(
					ctx,
					request.method,
					srv.URL+request.path,
					body,
				)
				require.NoError(t, err)

				if request.headers != nil {
					req.Header = request.headers.Clone()
				}

				resp, err := client.Do(req)
				require.NoError(t, err)

				responseBody, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())

				actualBodies = append(actualBodies, string(responseBody))
			}

			assert.Equal(t, tc.expectedOriginHits, originHits.Load())
			assert.Equal(t, tc.expectedBodies, actualBodies)
		})
	}
}

func TestRoundTripperRoundTripWithoutCacheInContext(t *testing.T) {
	t.Parallel()

	// GIVEN
	var originHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit := originHits.Add(1)

		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = fmt.Fprintf(w, "origin-hit-%d", hit)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &RoundTripper{
		Transport: http.DefaultTransport,
	}}

	bodies := make([]string, 0, 2)

	// WHEN
	for range 2 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		bodies = append(bodies, string(body))
	}

	// THEN
	assert.Equal(t, int32(2), originHits.Load())
	assert.Equal(t, []string{"origin-hit-1", "origin-hit-2"}, bodies)
}

type cachedValue struct {
	value     []byte
	expiresAt time.Time
}

func newStatefulCacheMock(t *testing.T) *cachemocks.CacheMock {
	t.Helper()

	cch := cachemocks.NewCacheMock(t)
	entries := make(map[string]cachedValue)

	var mutex sync.Mutex

	cch.EXPECT().Get(mock.Anything, mock.AnythingOfType("string")).
		RunAndReturn(func(_ context.Context, key string) ([]byte, error) {
			mutex.Lock()
			defer mutex.Unlock()

			entry, ok := entries[key]
			if !ok || !entry.expiresAt.After(time.Now()) {
				delete(entries, key)

				return nil, ErrNoCacheEntry
			}

			return bytes.Clone(entry.value), nil
		}).
		Maybe()

	cch.EXPECT().Set(
		mock.Anything,
		mock.AnythingOfType("string"),
		mock.Anything,
		mock.AnythingOfType("time.Duration"),
	).
		RunAndReturn(func(_ context.Context, key string, value []byte, ttl time.Duration) error {
			mutex.Lock()
			defer mutex.Unlock()

			entries[key] = cachedValue{
				value:     bytes.Clone(value),
				expiresAt: time.Now().Add(ttl),
			}

			return nil
		}).
		Maybe()

	return cch
}

func TestRoundTripperStoreResponsePublishesImmutableResponseEntries(t *testing.T) {
	t.Parallel()

	// GIVEN
	cch := cachemocks.NewCacheMock(t)
	req, err := http.NewRequestWithContext(
		cache.WithContext(t.Context(), cch),
		http.MethodGet,
		"https://example.com/resource",
		nil,
	)
	require.NoError(t, err)

	cacheReq := newCacheableRequest(req)
	selector := cacheReq.selector(nil)

	var (
		responseKeys []string
		indexDumps   [][]byte
	)

	cch.EXPECT().Get(mock.Anything, cacheReq.indexKey).
		Return(nil, ErrNoCacheEntry).
		Twice()
	cch.EXPECT().Set(
		mock.Anything,
		mock.AnythingOfType("string"),
		mock.Anything,
		mock.MatchedBy(func(ttl time.Duration) bool { return ttl > 0 }),
	).
		RunAndReturn(func(_ context.Context, key string, value []byte, _ time.Duration) error {
			if key == cacheReq.indexKey {
				indexDumps = append(indexDumps, bytes.Clone(value))
			} else {
				responseKeys = append(responseKeys, key)
			}

			return nil
		}).
		Times(4)

	newResponse := func(body string) *http.Response {
		return &http.Response{
			Status:     "200 OK",
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Cache-Control": {"max-age=60"},
			},
			Body:    io.NopCloser(strings.NewReader(body)),
			Request: req,
		}
	}

	rt := &RoundTripper{}

	// WHEN
	rt.storeResponse(cacheReq, newResponse("response-a")) //nolint:bodyclose
	rt.storeResponse(cacheReq, newResponse("response-b")) //nolint:bodyclose

	// THEN
	require.Len(t, responseKeys, 2)
	require.Len(t, indexDumps, 2)
	assert.NotEqual(t, responseKeys[0], responseKeys[1])

	responseIDs := make([]string, 0, len(indexDumps))
	for index, indexDump := range indexDumps {
		decoded, err := decodeVariantIndex(indexDump)
		require.NoError(t, err)
		require.Len(t, decoded.Groups, 1)
		require.Len(t, decoded.Groups[0].Entries, 1)

		entry := decoded.Groups[0].Entries[0]
		assert.NotEmpty(t, entry.ResponseID)
		assert.Equal(
			t,
			storedResponseKey(cacheReq.targetID, nil, selector, entry.ResponseID),
			responseKeys[index],
		)
		responseIDs = append(responseIDs, entry.ResponseID)
	}

	assert.NotEqual(t, responseIDs[0], responseIDs[1])
}

func TestRoundTripperLookupCachedResponseUsesIndexedResponseID(t *testing.T) {
	t.Parallel()

	// GIVEN
	cch := cachemocks.NewCacheMock(t)
	req, err := http.NewRequestWithContext(
		cache.WithContext(t.Context(), cch),
		http.MethodGet,
		"https://example.com/resource",
		nil,
	)
	require.NoError(t, err)

	cacheReq := newCacheableRequest(req)
	selector := cacheReq.selector(nil)
	responseID := "response-a"
	entry := variant{
		Selector:     selector,
		ResponseID:   responseID,
		ExpiresAt:    time.Now().Add(time.Minute).UnixNano(),
		ResponseDate: time.Now().UnixNano(),
		StoredAt:     time.Now().UnixNano(),
	}
	indexDump, err := json.Marshal(variantIndex{
		Version: variantIndexFormatVersion,
		Groups: []variantGroup{
			{Entries: []variant{entry}},
		},
	})
	require.NoError(t, err)

	cachedResponse := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("response-a")),
		ContentLength: int64(len("response-a")),
	}
	responseDump, err := httputil.DumpResponse(cachedResponse, true)
	require.NoError(t, err)

	responseKey := storedResponseKey(cacheReq.targetID, nil, selector, responseID)
	cch.EXPECT().Get(mock.Anything, cacheReq.indexKey).
		Return(indexDump, nil).
		Once()
	cch.EXPECT().Get(mock.Anything, responseKey).
		Return(responseDump, nil).
		Once()

	// WHEN
	resp, err := (&RoundTripper{}).lookupCachedResponse(cacheReq)

	// THEN
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "response-a", string(body))
}

func TestRoundTripperRoundTripHandlesCacheFailures(t *testing.T) {
	t.Parallel()

	backendErr := errors.New("cache backend failed")

	t.Run("should fall back to transport on cache miss", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		var originHits atomic.Int32

		cch := cachemocks.NewCacheMock(t)
		cch.EXPECT().Get(mock.Anything, mock.AnythingOfType("string")).
			Return(nil, ErrNoCacheEntry).
			Once()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			originHits.Add(1)
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, "origin")
		}))
		t.Cleanup(srv.Close)

		client := &http.Client{Transport: &RoundTripper{
			Transport: http.DefaultTransport,
		}}

		req, err := http.NewRequestWithContext(
			cache.WithContext(t.Context(), cch),
			http.MethodGet,
			srv.URL,
			nil,
		)
		require.NoError(t, err)

		// WHEN
		resp, err := client.Do(req)

		// THEN
		require.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "origin", string(body))
		assert.Equal(t, int32(1), originHits.Load())
	})

	t.Run("should fall back to transport on cache lookup error", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		var originHits atomic.Int32

		cch := cachemocks.NewCacheMock(t)
		cch.EXPECT().Get(mock.Anything, mock.AnythingOfType("string")).
			Return(nil, backendErr).
			Once()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			originHits.Add(1)
			w.Header().Set("Cache-Control", "no-store")
			_, _ = io.WriteString(w, "origin")
		}))
		t.Cleanup(srv.Close)

		client := &http.Client{Transport: &RoundTripper{
			Transport: http.DefaultTransport,
		}}

		req, err := http.NewRequestWithContext(
			cache.WithContext(t.Context(), cch),
			http.MethodGet,
			srv.URL,
			nil,
		)
		require.NoError(t, err)

		// WHEN
		resp, err := client.Do(req)

		// THEN
		require.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "origin", string(body))
		assert.Equal(t, int32(1), originHits.Load())
	})

	t.Run("should return origin response when storing response fails", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		cch := cachemocks.NewCacheMock(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "max-age=60")
			_, _ = io.WriteString(w, "origin")
		}))
		t.Cleanup(srv.Close)

		req, err := http.NewRequestWithContext(
			cache.WithContext(t.Context(), cch),
			http.MethodGet,
			srv.URL,
			nil,
		)
		require.NoError(t, err)

		cacheReq := newCacheableRequest(req)

		cch.EXPECT().Get(mock.Anything, cacheReq.indexKey).
			Return(nil, ErrNoCacheEntry).
			Once()
		cch.EXPECT().Set(
			mock.Anything,
			mock.MatchedBy(func(key string) bool { return key != cacheReq.indexKey }),
			mock.Anything,
			mock.MatchedBy(func(ttl time.Duration) bool { return ttl > 0 }),
		).
			Return(backendErr).
			Once()

		client := &http.Client{Transport: &RoundTripper{
			Transport: http.DefaultTransport,
		}}

		// WHEN
		resp, err := client.Do(req)

		// THEN
		require.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "origin", string(body))
	})

	t.Run("should ignore variant index update failure", func(t *testing.T) {
		t.Parallel()

		// GIVEN
		cch := cachemocks.NewCacheMock(t)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "max-age=60")
			_, _ = io.WriteString(w, "origin")
		}))
		t.Cleanup(srv.Close)

		req, err := http.NewRequestWithContext(
			cache.WithContext(t.Context(), cch),
			http.MethodGet,
			srv.URL,
			nil,
		)
		require.NoError(t, err)

		cacheReq := newCacheableRequest(req)

		cch.EXPECT().Get(mock.Anything, cacheReq.indexKey).
			Return(nil, ErrNoCacheEntry).
			Twice()
		cch.EXPECT().Set(
			mock.Anything,
			mock.MatchedBy(func(key string) bool { return key != cacheReq.indexKey }),
			mock.Anything,
			mock.MatchedBy(func(ttl time.Duration) bool { return ttl > 0 }),
		).
			Return(nil).
			Once()
		cch.EXPECT().Set(
			mock.Anything,
			cacheReq.indexKey,
			mock.Anything,
			mock.MatchedBy(func(ttl time.Duration) bool { return ttl > 0 }),
		).
			Return(backendErr).
			Once()

		client := &http.Client{Transport: &RoundTripper{
			Transport: http.DefaultTransport,
		}}

		// WHEN
		resp, err := client.Do(req)

		// THEN
		require.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "origin", string(body))
	})
}
