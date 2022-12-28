package config

type DefaultRule struct {
	Methods      []string          `koanf:"methods"`
	Execute      []MechanismConfig `koanf:"execute"`
	ErrorHandler []MechanismConfig `koanf:"on_error"`
}
