package admissioncontroller

import (
	"fmt"

	"github.com/dadrus/heimdall/internal/config"
)

type Config struct {
	Enabled bool       `mapstructure:"enabled"`
	Host    string     `mapstructure:"host"`
	Port    int        `mapstructure:"port"`
	TLS     config.TLS `mapstructure:"tls"`
}

func (c Config) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }
