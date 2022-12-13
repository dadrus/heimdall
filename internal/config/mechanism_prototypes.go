package config

type MechanismPrototypes struct {
	Authenticators  []Mechanism `koanf:"authenticators"`
	Authorizers     []Mechanism `koanf:"authorizers"`
	Contextualizers []Mechanism `koanf:"contextualizers"`
	Unifiers        []Mechanism `koanf:"unifiers"`
	ErrorHandlers   []Mechanism `koanf:"error_handlers"`
}
