package config

type RuleConfig struct {
	ID               string           `yaml:"id"`
	URL              string           `yaml:"url"`
	MatchingStrategy string           `yaml:"matching_strategy"`
	Methods          []string         `yaml:"methods"`
	Pipeline         []map[string]any `yaml:"execute"`
	ErrorHandler     []map[string]any `yaml:"on_error"`
}
