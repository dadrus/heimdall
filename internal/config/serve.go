package config

import (
	"fmt"
	"time"
)

type Timeout struct {
	Read  time.Duration `koanf:"read"`
	Write time.Duration `koanf:"write"`
	Idle  time.Duration `koanf:"idle"`
}

type CORS struct {
	AllowedOrigins   []string      `koanf:"allowed_origins"`
	AllowedMethods   []string      `koanf:"allowed_methods"`
	AllowedHeaders   []string      `koanf:"allowed_headers"`
	ExposedHeaders   []string      `koanf:"exposed_headers"`
	AllowCredentials bool          `koanf:"allow_credentials"`
	MaxAge           time.Duration `koanf:"max_age"`
}

type TLS struct {
	Key  string `koanf:"key"`
	Cert string `koanf:"cert"`
}

type ServiceConfig struct {
	Host           string    `koanf:"host"`
	Port           int       `koanf:"port"`
	VerboseErrors  bool      `koanf:"verbose_errors"`
	Timeout        Timeout   `koanf:"timeout"`
	CORS           *CORS     `koanf:"cors"`
	TLS            *TLS      `koanf:"tls"`
	TrustedProxies *[]string `koanf:"trusted_proxies"`
}

func (c ServiceConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }

type ServeConfig struct {
	Proxy       ServiceConfig `koanf:"proxy"`
	DecisionAPI ServiceConfig `koanf:"api"`
}
