package config

import (
	"fmt"
)

type PrometheusConfig struct {
	Host        string `koanf:"host"`
	Port        int    `koanf:"port"`
	MetricsPath string `koanf:"metrics_path"`
}

func (c PrometheusConfig) Address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }
