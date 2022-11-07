package config

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTLSMinVersionOrDefault(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		version  TLSMinVersion
		expected uint16
	}{
		{uc: "not configured", expected: tls.VersionTLS13},
		{uc: "configured", version: tls.VersionTLS12, expected: tls.VersionTLS12},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.version.OrDefault())
		})
	}
}

func TestTLSCipherSuitesOrDefault(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		suites   TLSCipherSuites
		expected []uint16
	}{
		{
			uc: "not configured",
			expected: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		{
			uc:     "configured",
			suites: TLSCipherSuites{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			expected: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.suites.OrDefault())
		})
	}
}
