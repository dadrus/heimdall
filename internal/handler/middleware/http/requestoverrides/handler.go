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

package requestoverrides

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/x/httpx"
)

// New returns a middleware that rejects requests with unsafe host authority
// values or ambiguous request override headers with 400 Bad Request.
func New() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !httpx.IsValidAuthority(r.Host) {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			forwardedHosts := r.Header["X-Forwarded-Host"]

			if len(forwardedHosts) > 1 ||
				len(r.Header["X-Forwarded-Method"]) > 1 ||
				len(r.Header["X-Forwarded-Proto"]) > 1 ||
				len(r.Header["X-Forwarded-Uri"]) > 1 {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			if len(forwardedHosts) > 0 && !httpx.IsValidAuthority(forwardedHosts[0]) {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
