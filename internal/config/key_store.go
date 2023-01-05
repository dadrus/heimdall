package config

type KeyStore struct {
	Path     string `koanf:"path"`
	Password string `koanf:"password"`
}
