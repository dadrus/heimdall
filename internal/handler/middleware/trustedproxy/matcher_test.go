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
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestMatcherContains(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		proxies    []string
		ip         string
		expected   bool
		warningLog string
	}{
		"bad IP range": {
			proxies:    []string{"/128"},
			ip:         "127.0.0.1",
			expected:   false,
			warningLog: "could not be parsed",
		},
		"single IP trusted": {
			proxies:  []string{"127.0.0.1"},
			ip:       "127.0.0.1",
			expected: true,
		},
		"trusted IP range": {
			proxies:  []string{"127.0.0.0/24"},
			ip:       "127.0.0.1",
			expected: true,
		},
		"source in insecure IPv4 range": {
			proxies:    []string{"172.0.0.0/0"},
			ip:         "127.0.0.1",
			expected:   true,
			warningLog: "trusted proxies contains insecure",
		},
		"source not in insecure IPv6 range 1": {
			proxies:    []string{"::/0"},
			ip:         "127.0.0.1",
			expected:   false,
			warningLog: "trusted proxies contains insecure",
		},
		"source not in insecure IPv6 range 2": {
			proxies:    []string{"3209:7473:73ed:a31c:0a08:f214:2434:d5ce/0"},
			ip:         "127.0.0.1",
			expected:   false,
			warningLog: "trusted proxies contains insecure",
		},
		"source not in IPv4 range": {
			proxies:  []string{"172.0.0.0/24"},
			ip:       "127.0.0.1",
			expected: false,
		},
		"empty list": {
			proxies:  []string{},
			ip:       "127.0.0.1",
			expected: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			tb := &testsupport.TestingLog{TB: t}
			logger := zerolog.New(zerolog.TestWriter{T: tb})
			matcher := NewMatcher(logger, tc.proxies...)

			// WHEN
			matches := matcher.Contains(net.ParseIP(tc.ip))

			// THEN
			require.Equal(t, tc.expected, matches)

			logs := tb.CollectedLog()
			if len(tc.warningLog) != 0 {
				assert.Contains(t, logs, tc.warningLog)
			} else {
				require.Empty(t, logs)
			}
		})
	}
}
