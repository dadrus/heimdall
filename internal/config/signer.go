package config

type Signer struct {
	File     string `koanf:"key_store"`
	Password string `koanf:"password"`
	KeyID    string `koanf:"key_id"`
}
