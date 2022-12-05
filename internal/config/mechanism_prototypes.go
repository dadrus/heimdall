package config

type MechanismPrototypes struct {
	Authenticators []Mechanism `koanf:"authenticators"`
	Authorizers    []Mechanism `koanf:"authorizers"`
	Hydrators      []Mechanism `koanf:"hydrators"`
	Mutators       []Mechanism `koanf:"mutators"`
	ErrorHandlers  []Mechanism `koanf:"error_handlers"`
}
