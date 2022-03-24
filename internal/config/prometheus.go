package config

import "strconv"

type Prometheus struct {
	Host                 string `koanf:"host"`
	Port                 int    `koanf:"port"`
	MetricsPath          string `koanf:"metrics_path"`
	CollapseRequestPaths bool   `koanf:"collapse_request_paths"`
}

func (c Prometheus) Address() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}
