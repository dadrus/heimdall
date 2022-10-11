package config

type RuleProviders struct {
	FileSystem *FileBasedRuleProviderConfig `koanf:"file_system,omitempty"`
}

type FileBasedRuleProviderConfig struct {
	Src   string `koanf:"src"`
	Watch bool   `koanf:"watch"`
}
