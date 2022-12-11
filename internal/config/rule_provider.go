package config

type RuleProviders struct {
	FileSystem   map[string]any `koanf:"file_system,omitempty"`
	HTTPEndpoint map[string]any `koanf:"http_endpoint,omitempty"`
	CloudBlob    map[string]any `koanf:"cloud_blob,omitempty"`
	Kubernetes   map[string]any `koanf:"kubernetes,omitempty"`
}
