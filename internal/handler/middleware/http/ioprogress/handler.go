// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package ioprogress

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

func New(log zerolog.Logger, opts ...Option) func(http.Handler) http.Handler {
	conf := newConfig(opts...)
	requestBodyReadEnabled := conf.requestBodyReadIdleTimeout > 0
	responseWriteEnabled := conf.responseWriteIdleTimeout > 0

	if !requestBodyReadEnabled && !responseWriteEnabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if responseWriteEnabled {
				var state *responseWriter
				rw, state = wrapResponseWriter(
					rw,
					newDeadlineTracker(
						conf.responseWriteTimeout,
						conf.responseWriteIdleTimeout,
						conf.responseWriteMinRate,
						time.Now(),
					),
					&log,
				)
				defer state.finishRequest()
			}

			if requestBodyReadEnabled {
				wrapRequestBody(
					req,
					rw,
					conf.requestReadTimeout,
					conf.requestBodyReadIdleTimeout,
					conf.requestBodyReadMinRate,
				)
			}

			next.ServeHTTP(rw, req)
		})
	}
}
