package config

type TLS struct {
	Key  string `koanf:"key"`
	Cert string `koanf:"cert"`
}
