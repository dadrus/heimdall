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

package requestlimit

import (
	"errors"
	"net/http"

	"github.com/dadrus/heimdall/internal/accesscontext"
	limit "github.com/dadrus/heimdall/internal/handler/middleware/requestlimit"
)

var errServiceOverloaded = errors.New("service overloaded") //nolint:gochecknoglobals

type RejectHandler func(http.ResponseWriter, *http.Request)

type Option func(*options)

type options struct {
	reject RejectHandler
}

func WithRejectHandler(handler RejectHandler) Option {
	return func(opts *options) {
		if handler != nil {
			opts.reject = handler
		}
	}
}

func New(maxInFlight int64, opts ...Option) func(http.Handler) http.Handler {
	if maxInFlight == 0 {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	conf := options{
		reject: func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusServiceUnavailable)
		},
	}

	for _, opt := range opts {
		opt(&conf)
	}

	limiter := limit.New(maxInFlight)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if !limiter.TryAcquire() {
				accesscontext.SetError(req.Context(), errServiceOverloaded)
				conf.reject(rw, req)

				return
			}

			defer limiter.Release()

			next.ServeHTTP(rw, req)
		})
	}
}
