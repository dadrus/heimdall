package config

type MechanismPrototypes struct {
	Authenticators  []Mechanism `koanf:"authenticators"`
	Authorizers     []Mechanism `koanf:"authorizers"`
	Contextualizers []Mechanism `koanf:"contextualizers"`
	Mutators        []Mechanism `koanf:"mutators"`
	ErrorHandlers   []Mechanism `koanf:"error_handlers"`
}
