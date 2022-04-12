package config

import (
	"strconv"
	"time"
)

type Timeout struct {
	Read  time.Duration `koanf:"read"`
	Write time.Duration `koanf:"write"`
	Idle  time.Duration `koanf:"idle"`
}

type CORS struct {
	AllowedOrigins   []string `koanf:"allowed_origins"`
	AllowedMethods   []string `koanf:"allowed_methods"`
	AllowedHeaders   []string `koanf:"allowed_headers"`
	ExposedHeaders   []string `koanf:"exposed_headers"`
	AllowCredentials bool     `koanf:"allow_credentials"`
	MaxAge           int      `koanf:"max_age"`
}

type TLS struct {
	Key  string `koanf:"key"`
	Cert string `koanf:"cert"`
}

type Serve struct {
	Host          string  `koanf:"host"`
	Port          int     `koanf:"port"`
	VerboseErrors bool    `koanf:"verbose_errors"`
	Timeout       Timeout `koanf:"timeout"`
	CORS          *CORS   `koanf:"cors"`
	TLS           *TLS    `koanf:"tls"`
}

func (c Serve) Address() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}
