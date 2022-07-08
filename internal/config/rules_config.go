package config

type RulesConfig struct {
	Default   *DefaultRuleConfig `koanf:"default,omitempty"`
	Providers RuleProviders      `koanf:"providers"`
}
