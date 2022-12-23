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
	KeyStore     string          `koanf:"key_store"`
	Password     string          `koanf:"password"`
	KeyID        string          `koanf:"key_id"`
	CipherSuites TLSCipherSuites `koanf:"cipher_suites"`
	MinVersion   TLSMinVersion   `koanf:"min_version"`
}

type ServiceConfig struct {
	Host           string        `koanf:"host"`
	Port           int           `koanf:"port"`
	Timeout        Timeout       `koanf:"timeout"`
	CORS           *CORS         `koanf:"cors,omitempty"`
	TLS            *TLS          `koanf:"tls,omitempty"`
	TrustedProxies *[]string     `koanf:"trusted_proxies,omitempty"`
	Respond        RespondConfig `koanf:"respond"`
}

func (c ServiceConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }

type ServeConfig struct {
	Proxy      ServiceConfig `koanf:"proxy"`
	Decision   ServiceConfig `koanf:"decision"`
	Management ServiceConfig `koanf:"management"`
}

type ResponseOverride struct {
	Code int `koanf:"code"`
}

type RespondConfig struct {
	Verbose bool `koanf:"verbose"`
	With    struct {
		Accepted            ResponseOverride `koanf:"accepted"`
		ArgumentError       ResponseOverride `koanf:"argument_error"`
		AuthenticationError ResponseOverride `koanf:"authentication_error"`
		AuthorizationError  ResponseOverride `koanf:"authorization_error"`
		BadMethodError      ResponseOverride `koanf:"method_error"`
		CommunicationError  ResponseOverride `koanf:"communication_error"`
		InternalError       ResponseOverride `koanf:"internal_error"`
		NoRuleError         ResponseOverride `koanf:"no_rule_error"`
	} `koanf:"with"`
}
