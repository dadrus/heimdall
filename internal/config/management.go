package config

import "fmt"

type ManagementConfig struct {
	Host        string      `koanf:"host"`
	Port        int         `koanf:"port"`
	Timeout     Timeout     `koanf:"timeout"`
	BufferLimit BufferLimit `koanf:"buffer_limit"`
	CORS        *CORS       `koanf:"cors,omitempty"`
	TLS         *TLS        `koanf:"tls,omitempty"  validate:"enforced=notnil"`
}

func (c ManagementConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }
