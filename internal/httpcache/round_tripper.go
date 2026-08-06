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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
)

const (
	// Bump the namespace whenever the request-target identity, variant selector,
	// cache-key derivation or variant-index format changes. v6 groups variants
	// by their normalized Vary field set so selectors are calculated once per
	// group during lookup.
	cacheKeyNamespace = "heimdall-http-cache:v6"

	variantIndexFormatVersion  = 2
	maxVariantIndexSize        = 1 << 20
	maxVariantEntriesPerTarget = 128
)

type responseCacheMetadata struct {
	Vary      []string
	ExpiresAt time.Time
}

type RoundTripper struct {
	// Transport is the next RoundTripper in the chain. It is used for cache
	// misses and requests that bypass the cache. If nil, http.DefaultTransport
	// is used.
	Transport http.RoundTripper

	// Cache stores variant indexes and serialized HTTP responses. It must be
	// configured and honor the TTL supplied to Set.
	Cache Cache

	// FallbackCacheTTL defines how long an otherwise cacheable response is
	// considered fresh when no expiration time can be derived from its HTTP
	// headers. A non-positive value prevents storing such responses.
	FallbackCacheTTL time.Duration

	// UncacheableVaryHeaders lists request field names for which a response must
	// not be stored when the origin names one of them in Vary. The fields are not
	// ignored: ignoring an origin-provided Vary field would permit an incorrect
	// cache hit. This option is useful for volatile fields such as Signature,
	// Signature-Input or traceparent.
	UncacheableVaryHeaders []string
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := rt.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	if rt.Cache == nil {
		return nil, ErrCacheNotConfigured
	}

	// pquerna/cachecontrol can classify explicitly fresh POST responses as
	// cacheable. This implementation deliberately supports reuse only for
	// bodyless GET and HEAD requests. It has no safe POST/body-key semantics.
	if !isCacheEligibleRequest(req) {
		return transport.RoundTrip(req)
	}

	cacheReq := newCacheableRequest(req)

	// Request cache directives and conditional/range requests apply before a
	// cache lookup. Cacheability is only evaluated after an origin request, so it
	// cannot protect the lookup path.
	if !shouldBypassCache(req) {
		resp, err := rt.lookupCachedResponse(cacheReq)
		if err == nil {
			return resp, nil
		}
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	rt.storeResponse(cacheReq, resp)

	return resp, nil
}

func (rt *RoundTripper) lookupCachedResponse(req cacheableRequest) (*http.Response, error) {
	ctx := req.request.Context()
	indexDump, err := rt.Cache.Get(ctx, req.indexKey)
	if err != nil {
		return nil, ErrNoCacheEntry
	}

	index, err := decodeVariantIndex(indexDump)
	if err != nil {
		return nil, ErrNoCacheEntry
	}

	now := time.Now().UnixNano()
	matchingGroups := index.Groups[:0]

	for _, group := range index.Groups {
		if !rt.supportsVary(group.Vary, req.connectionFields) {
			continue
		}

		// All variants in a group share the same Vary field set, so the current
		// request selector only needs to be calculated once for the whole group.
		candidate, ok := group.mostRecentMatch(req.selector(group.Vary), now)
		if !ok {
			continue
		}

		// Reuse the decoded index storage as a scratch area. Each matching group
		// only needs to retain its single matching variant.
		group.Entries = group.Entries[:1]
		group.Entries[0] = candidate
		matchingGroups = append(matchingGroups, group)
	}

	for len(matchingGroups) != 0 {
		groupIndex := mostRecentVariantGroup(matchingGroups)
		group := matchingGroups[groupIndex]
		candidate := group.Entries[0]

		// Order no longer matters after candidate selection, so remove the group
		// without shifting the remaining elements.
		last := len(matchingGroups) - 1
		matchingGroups[groupIndex] = matchingGroups[last]
		matchingGroups = matchingGroups[:last]

		responseKey := storedResponseKey(req.targetID, group.Vary, candidate.Selector)
		respDump, err := rt.Cache.Get(ctx, responseKey)
		if err != nil {
			continue
		}

		resp, err := http.ReadResponse(
			bufio.NewReader(bytes.NewReader(respDump)),
			req.request,
		)
		if err != nil {
			// A malformed or corrupt response entry behaves as a miss. Another
			// matching index group can still be usable.
			continue
		}

		return resp, nil
	}

	return nil, ErrNoCacheEntry
}

func (rt *RoundTripper) storeResponse(req cacheableRequest, resp *http.Response) {
	now := time.Now()
	metadata, ok := rt.responseCacheMetadata(req, resp, now)
	if !ok {
		return
	}

	ttl := metadata.ExpiresAt.Sub(now)
	if ttl <= 0 {
		return
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return
	}

	selector := req.selector(metadata.Vary)
	responseKey := storedResponseKey(req.targetID, metadata.Vary, selector)
	ctx := req.request.Context()

	// Publish the response before its index entry. A concurrent lookup can at
	// worst miss the new variant, but never select an entry whose response has
	// not yet been stored.
	if err = rt.Cache.Set(ctx, responseKey, respDump, ttl); err != nil {
		return
	}

	rt.updateVariantIndex(ctx, req.indexKey, metadata.Vary, variant{
		Selector:     selector,
		ExpiresAt:    metadata.ExpiresAt.UnixNano(),
		ResponseDate: responseDate(resp, now).UnixNano(),
		StoredAt:     now.UnixNano(),
	})
}

func (rt *RoundTripper) updateVariantIndex(
	ctx context.Context,
	indexKey string,
	vary []string,
	stored variant,
) {
	index := rt.loadVariantIndex(ctx, indexKey)
	now := time.Now()
	index.merge(vary, stored, now.UnixNano())

	indexDump, err := json.Marshal(index)
	if err != nil || len(indexDump) > maxVariantIndexSize {
		return
	}

	ttl := index.ttl(now)
	if ttl <= 0 {
		return
	}

	_ = rt.Cache.Set(ctx, indexKey, indexDump, ttl)
}

func (rt *RoundTripper) loadVariantIndex(ctx context.Context, indexKey string) variantIndex {
	empty := variantIndex{Version: variantIndexFormatVersion}

	data, err := rt.Cache.Get(ctx, indexKey)
	if err != nil {
		return empty
	}

	index, err := decodeVariantIndex(data)
	if err != nil {
		return empty
	}

	return index
}

func (rt *RoundTripper) responseCacheMetadata(
	req cacheableRequest,
	resp *http.Response,
	now time.Time,
) (responseCacheMetadata, bool) {
	if req.request.Header.Get("Range") != "" ||
		hasConditionalHeaders(req.request.Header) ||
		resp.StatusCode == http.StatusPartialContent ||
		resp.StatusCode == http.StatusNotModified {
		return responseCacheMetadata{}, false
	}

	// Replaying Set-Cookie from a shared cache can create session leaks or
	// session fixation.
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		return responseCacheMetadata{}, false
	}

	vary, ok := parseVary(resp.Header)
	if !ok || !rt.supportsVary(vary, req.connectionFields) {
		return responseCacheMetadata{}, false
	}

	// Host is already included in the request-target identity. The Vary slice is
	// no longer needed in its original form, so remove Host in place.
	vary = slices.DeleteFunc(vary, func(field string) bool {
		return field == "Host"
	})

	expires, ok := rt.responseExpiration(req.request, resp, now)
	if !ok {
		return responseCacheMetadata{}, false
	}

	return responseCacheMetadata{
		Vary:      vary,
		ExpiresAt: expires,
	}, true
}

func (rt *RoundTripper) responseExpiration(
	req *http.Request,
	resp *http.Response,
	now time.Time,
) (time.Time, bool) {
	reasons, expires, _, object, err := cacheobject.UsingRequestResponseWithObject(
		req,
		resp.StatusCode,
		resp.Header,
		false,
	)
	if err != nil || len(reasons) != 0 {
		return time.Time{}, false
	}

	if object == nil ||
		object.RespDirectives == nil ||
		object.RespDirectives.NoCachePresent {
		return time.Time{}, false
	}

	if !expires.IsZero() {
		return expires, true
	}

	if rt.FallbackCacheTTL <= 0 {
		return time.Time{}, false
	}

	return now.Add(rt.FallbackCacheTTL), true
}

func (rt *RoundTripper) supportsVary(
	vary []string,
	connectionFields map[string]struct{},
) bool {
	for _, field := range vary {
		if isConnectionSpecificField(field) {
			return false
		}

		if _, ok := connectionFields[field]; ok {
			return false
		}

		for _, configured := range rt.UncacheableVaryHeaders {
			if strings.EqualFold(strings.TrimSpace(configured), field) {
				return false
			}
		}
	}

	return true
}

func isCacheEligibleRequest(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}

	return req.Body == nil || req.Body == http.NoBody
}

func shouldBypassCache(req *http.Request) bool {
	if req.Header.Get("Range") != "" || hasConditionalHeaders(req.Header) {
		return true
	}

	if requestCacheControlRequiresBypass(req.Header) {
		return true
	}

	// RFC 9111 keeps Pragma: no-cache for HTTP/1.0 compatibility.
	for _, value := range req.Header.Values("Pragma") {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "no-cache") {
				return true
			}
		}
	}

	return false
}

func requestCacheControlRequiresBypass(header http.Header) bool {
	value := strings.Join(header.Values("Cache-Control"), ",")
	if len(value) == 0 {
		return false
	}

	directives, err := cacheobject.ParseRequestCacheControl(value)
	if err != nil {
		return true
	}

	// no-cache and no-store prohibit normal reuse. max-age and min-fresh are
	// request-specific freshness constraints that this implementation does not
	// currently evaluate against individual cached variants.
	return directives.NoCache ||
		directives.NoStore ||
		directives.MaxAge >= 0 ||
		directives.MinFresh >= 0
}

func hasConditionalHeaders(header http.Header) bool {
	for _, name := range []string{
		"If-Match",
		"If-Modified-Since",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
	} {
		if header.Get(name) != "" {
			return true
		}
	}

	return false
}

func parseVary(header http.Header) ([]string, bool) {
	values := header.Values("Vary")
	if len(values) == 0 {
		return nil, true
	}

	fields := make([]string, 0, len(values))
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			name := strings.TrimSpace(part)
			if name == "*" || !validFieldName(name) {
				return nil, false
			}

			fields = append(fields, http.CanonicalHeaderKey(name))
		}
	}

	slices.Sort(fields)

	return slices.Compact(fields), true
}

func responseDate(resp *http.Response, fallback time.Time) time.Time {
	value := resp.Header.Get("Date")
	if value == "" {
		return fallback
	}

	parsed, err := http.ParseTime(value)
	if err != nil {
		return fallback
	}

	return parsed
}

func isConnectionSpecificField(name string) bool {
	switch name {
	case "Connection", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func validFieldName(value string) bool {
	if len(value) == 0 {
		return false
	}

	for i := range len(value) {
		char := value[i]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') {
			continue
		}

		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}

	return true
}

func mostRecentVariantGroup(groups []variantGroup) int {
	mostRecent := 0

	for index := 1; index < len(groups); index++ {
		if groups[index].Entries[0].isMoreRecentThan(groups[mostRecent].Entries[0]) {
			mostRecent = index
		}
	}

	return mostRecent
}

