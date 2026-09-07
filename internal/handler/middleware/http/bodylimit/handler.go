// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package bodylimit

import (
	"net/http"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/inhies/go-bytesize"
)

// New returns a middleware that limits the number of bytes that can be read
// from a request body. A maxSize of zero disables the limit.
func New(maxSize bytesize.ByteSize) func(http.Handler) http.Handler {
	if maxSize == 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	limit := safecast.MustConvert[int64](maxSize)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.Body == nil {
				next.ServeHTTP(rw, req)

				return
			}

			if req.ContentLength > limit {
				rw.WriteHeader(http.StatusRequestEntityTooLarge)

				return
			}

			req.Body = http.MaxBytesReader(rw, req.Body, limit)

			next.ServeHTTP(rw, req)
		})
	}
}
