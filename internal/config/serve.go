package config

import (
	"crypto/tls"
	"fmt"
	"time"
)

type Timeout struct {
	Read  time.Duration `koanf:"read,string"`
	Write time.Duration `koanf:"write,string"`
	Idle  time.Duration `koanf:"idle,string"`
}

type CORS struct {
	AllowedOrigins   []string      `koanf:"allowed_origins"`
	AllowedMethods   []string      `koanf:"allowed_methods"`
	AllowedHeaders   []string      `koanf:"allowed_headers"`
	ExposedHeaders   []string      `koanf:"exposed_headers"`
	AllowCredentials bool          `koanf:"allow_credentials"`
	MaxAge           time.Duration `koanf:"max_age,string"`
}

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
	Key          string          `koanf:"key"`
	Cert         string          `koanf:"cert"`
	CipherSuites TLSCipherSuites `koanf:"cipher_suites"`
	MinVersion   TLSMinVersion   `koanf:"min_version"`
}

type ServiceConfig struct {
	Host           string    `koanf:"host"`
	Port           int       `koanf:"port"`
	VerboseErrors  bool      `koanf:"verbose_errors"`
	Timeout        Timeout   `koanf:"timeout"`
	CORS           *CORS     `koanf:"cors,omitempty"`
	TLS            *TLS      `koanf:"tls,omitempty"`
	TrustedProxies *[]string `koanf:"trusted_proxies,omitempty"`
}

func (c ServiceConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }

type ServeConfig struct {
	Proxy      ServiceConfig `koanf:"proxy"`
	Decision   ServiceConfig `koanf:"decision"`
	Management ServiceConfig `koanf:"management"`
}
