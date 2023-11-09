package config

import "crypto/tls"

type TLSCipherSuites []uint16

func (s TLSCipherSuites) OrDefault() []uint16 {
	if len(s) == 0 {
		return []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
	}

	return s
}

type TLSMinVersion uint16

func (v TLSMinVersion) OrDefault() uint16 {
	if v == 0 {
		return tls.VersionTLS13
	}

	return uint16(v)
}

type TLS struct {
	KeyStore     KeyStore        `koanf:"key_store"     mapstructure:"key_store"`
	KeyID        string          `koanf:"key_id"        mapstructure:"key_id"`
	CipherSuites TLSCipherSuites `koanf:"cipher_suites" mapstructure:"cipher_suites"`
	MinVersion   TLSMinVersion   `koanf:"min_version"   mapstructure:"min_version"`
}
