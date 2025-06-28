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
	"slices"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

var untrustedHeader = []string{ //nolint:gochecknoglobals
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Uri",
	"X-Forwarded-Path",
	"X-Forwarded-Method",
}

type ipHolder interface {
	Contains(ip net.IP) bool
}

type simpleIP net.IP

func (s simpleIP) Contains(ip net.IP) bool {
	return net.IP(s).Equal(ip)
}

type trustedProxySet []ipHolder

func (tpm trustedProxySet) Contains(ip net.IP) bool {
	for _, proxy := range tpm {
		if proxy.Contains(ip) {
			return true
		}
	}

	return false
}

func New(logger zerolog.Logger, proxies ...string) func(http.Handler) http.Handler {
	var ipHolders []ipHolder

	for _, ipAddr := range proxies {
		if !strings.Contains(ipAddr, "/") {
			ipHolders = append(ipHolders, simpleIP(net.ParseIP(ipAddr)))

			continue
		}

		_, ipNet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			logger.Warn().Err(err).
				Msgf("Trusted proxies entry %q could not be parsed and will be ignored", ipAddr)
		} else {
			ipHolders = append(ipHolders, ipNet)

			if slices.Contains(config.InsecureNetworks, ipNet.String()) {
				logger.Warn().Msgf("Configured trusted proxies contains insecure networks: %s", ipAddr)
			}
		}
	}

	trustedProxies := trustedProxySet(ipHolders)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if !trustedProxies.Contains(net.ParseIP(httpx.IPFromHostPort(req.RemoteAddr))) {
				for _, name := range untrustedHeader {
					req.Header.Del(name)
				}
			}

			next.ServeHTTP(rw, req)
		})
	}
}
