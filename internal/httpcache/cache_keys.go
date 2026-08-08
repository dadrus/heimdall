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

func variantIndexKey(targetID string) string {
	key := newKeyHash("variant-index")
	key.writeString(targetID)

	return key.sum()
}

func requestTargetID(req *http.Request) string {
	key := newKeyHash("request-target")
	key.writeString(req.Method)
	key.writeString(strings.ToLower(req.URL.Scheme))
	key.writeString(req.URL.Host)

	// Keep the connection target and an explicit Host override separate, but do
	// not write the same authority twice when no semantic override exists.
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		key.writeBool(true)
		key.writeString(req.Host)
	} else {
		key.writeBool(false)
	}

	// URL userinfo can cause net/http.Client to synthesize Authorization before
	// invoking this RoundTripper. It is not part of RequestURI, so preserve it as
	// an additional safety dimension even though userinfo should generally not be
	// used in HTTP URLs.
	if req.URL.User != nil {
		key.writeBool(true)
		key.writeString(req.URL.User.String())
	} else {
		key.writeBool(false)
	}

	key.writeString(req.URL.RequestURI())

	// Keep the value of the Authorization header as an additional local partitioning
	// dimension even when an origin forgets to emit Vary: Authorization for an explicitly
	// shared response.
	authorization := strings.TrimSpace(req.Header.Get("Authorization"))
	key.writeBool(authorization != "")

	if authorization != "" {
		key.writeString(authorization)
	}

	return key.sum()
}

func requestVariantSelector(req *http.Request, vary []string) string {
	key := newKeyHash("request-variant-selector")

	for _, field := range vary {
		values, present := req.Header[field]

		key.writeString(field)
		key.writeBool(present)
		key.writeUint64(uint64(len(values)))

		for _, value := range values {
			key.writeString(value)
		}
	}

	return key.sum()
}

func storedResponseKey(targetID string, vary []string, selector, responseID string) string {
	key := newKeyHash("stored-response")
	key.writeString(targetID)
	key.writeString(selector)
	key.writeString(responseID)
	key.writeUint64(uint64(len(vary)))

	for _, field := range vary {
		key.writeString(field)
	}

	return key.sum()
}
