package config

import "strconv"

type Serve struct {
	Host    string  `koanf:"host"`
	Port    int     `koanf:"port"`
	Timeout Timeout `koanf:"timeout"`
	CORS    *CORS   `koanf:"cors"`
	TLS     *TLS    `koanf:"tls"`
}

func (c Serve) Address() string {
	return c.Host + ":" + strconv.Itoa(c.Port)
}
