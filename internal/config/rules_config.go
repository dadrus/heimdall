package config

type RulesConfig struct {
	Prototypes *MechanismPrototypes `koanf:"mechanisms,omitempty"`
	Default    *DefaultRuleConfig   `koanf:"default,omitempty"`
	Providers  *RuleProviders       `koanf:"providers,omitempty"`
}
