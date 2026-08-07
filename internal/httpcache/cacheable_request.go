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
	"net/http"
	"strings"
)

// cacheableRequest contains the request and the derived values needed for
// cache lookup and storage. It does not imply that an origin response will
// necessarily be stored.
type cacheableRequest struct {
	request          *http.Request
	targetID         string
	indexKey         string
	connectionFields map[string]struct{}
}

func newCacheableRequest(req *http.Request) cacheableRequest {
	targetID := requestTargetID(req)

	return cacheableRequest{
		request:          req,
		targetID:         targetID,
		indexKey:         variantIndexKey(targetID),
		connectionFields: connectionSpecificFields(req.Header),
	}
}

func (req cacheableRequest) selector(vary []string) string {
	return requestVariantSelector(req.request, vary)
}

func connectionSpecificFields(header http.Header) map[string]struct{} {
	values := header.Values("Connection")
	if len(values) == 0 {
		return nil
	}

	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		for token := range strings.SplitSeq(value, ",") {
			name := strings.TrimSpace(token)
			if validFieldName(name) {
				result[http.CanonicalHeaderKey(name)] = struct{}{}
			}
		}
	}

	return result
}
