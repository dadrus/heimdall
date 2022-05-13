package config

type RulesConfig struct {
	Default  *DefaultRuleConfig `koanf:"default"`
	Provider RuleProvider       `koanf:"provider"`
}
