// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package config

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLSMinVersionOrDefault(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		uc       string
		version  TLSMinVersion
		expected uint16
	}{
		"not configured": {expected: tls.VersionTLS13},
		"configured":     {version: tls.VersionTLS12, expected: tls.VersionTLS12},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.version.OrDefault())
		})
	}
}

func TestTLSCipherSuitesOrDefault(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		suites   TLSCipherSuites
		expected []uint16
	}{
		"not configured": {
			expected: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		"configured": {
			suites: TLSCipherSuites{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			expected: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.suites.OrDefault())
		})
	}
}
