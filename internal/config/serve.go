package config

import (
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

type TLS struct {
	Key  string `koanf:"key"`
	Cert string `koanf:"cert"`
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
	Proxy       ServiceConfig `koanf:"proxy"`
	DecisionAPI ServiceConfig `koanf:"api"`
}
