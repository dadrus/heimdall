package config

type RuleConfig struct {
	Pipeline
	Id      string   `koanf:"id"`
	Url     string   `koanf:"url"`
	Methods []string `koanf:"methods"`
}
