package config

import "strconv"

type PrometheusConfig struct {
	Host        string `koanf:"host"`
	Port        int    `koanf:"port"`
	MetricsPath string `koanf:"metrics_path"`
}

func (c PrometheusConfig) Address() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}
