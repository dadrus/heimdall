package config

type RuleConfig struct {
	Pipeline
	ID      string   `koanf:"id"`
	URL     string   `koanf:"url"`
	Methods []string `koanf:"methods"`
}
