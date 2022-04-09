package config

type Signer struct {
	Name     string `koanf:"name"`
	KeyStore string `koanf:"key_store"`
	Password string `koanf:"password"`
	KeyID    string `koanf:"key_id"`
}
