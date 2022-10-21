package config

type RuleProviders struct {
	FileSystem   *FileBasedRuleProviderConfig `koanf:"file,omitempty"`
	HTTPEndpoint map[string]any               `koanf:"http_endpoint,omitempty"`
}

type FileBasedRuleProviderConfig struct {
	Src   string `koanf:"src"`
	Watch bool   `koanf:"watch"`
}
