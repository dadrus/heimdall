package config

type RulesConfig struct {
	Default   *DefaultRuleConfig `koanf:"default"`
	Providers RuleProviders      `koanf:"providers"`
}
