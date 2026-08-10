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

package trustedproxy

import (
	"net"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/middleware/trustedproxy"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

func New(logger zerolog.Logger, proxies ...string) func(http.Handler) http.Handler {
	matcher := trustedproxy.NewMatcher(logger, proxies...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			remoteIP := net.ParseIP(httpx.IPFromHostPort(req.RemoteAddr))

			if !matcher.Contains(remoteIP) {
				trustedproxy.RemoveForwardingHeaders(req.Header.Del)
			}

			next.ServeHTTP(rw, req)
		})
	}
}
