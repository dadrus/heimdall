package config

type RuleProviders struct {
	FileSystem   *FileBasedRuleProviderConfig `koanf:"file_system,omitempty"`
	HTTPEndpoint map[string]any               `koanf:"http_endpoint,omitempty"`
	CloudBlob    map[string]any               `koanf:"cloud_blob,omitempty"`
	Kubernetes   map[string]any               `koanf:"kubernetes,omitempty"`
}

type FileBasedRuleProviderConfig struct {
	Src   string `koanf:"src"`
	Watch bool   `koanf:"watch"`
}
