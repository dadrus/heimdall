package config

type Rules struct {
	Prototypes *MechanismPrototypes `koanf:"mechanisms,omitempty"`
	Default    *DefaultRule         `koanf:"default,omitempty"`
	Providers  RuleProviders        `koanf:"providers,omitempty"`
}
