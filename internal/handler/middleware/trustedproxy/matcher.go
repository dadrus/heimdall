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

package trustedproxy

import (
	"net"
	"slices"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
)

type ipHolder interface {
	Contains(ip net.IP) bool
}

type simpleIP net.IP

func (s simpleIP) Contains(ip net.IP) bool {
	return net.IP(s).Equal(ip)
}

type Matcher struct {
	proxies []ipHolder
}

func NewMatcher(logger zerolog.Logger, proxies ...string) *Matcher {
	holders := make([]ipHolder, 0, len(proxies))

	for _, ipAddr := range proxies {
		if !strings.Contains(ipAddr, "/") {
			holders = append(holders, simpleIP(net.ParseIP(ipAddr)))

			continue
		}

		_, ipNet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			logger.Warn().Err(err).
				Msgf("Trusted proxies entry %q could not be parsed and will be ignored", ipAddr)

			continue
		}

		holders = append(holders, ipNet)

		if slices.Contains(config.InsecureNetworks, ipNet.String()) {
			logger.Warn().
				Msgf("Configured trusted proxies contains insecure networks: %s", ipAddr)
		}
	}

	return &Matcher{proxies: holders}
}

func (m *Matcher) Contains(ip net.IP) bool {
	for _, proxy := range m.proxies {
		if proxy.Contains(ip) {
			return true
		}
	}

	return false
}
