package config

type PipelineObjectReference struct {
	ID     string         `koanf:"id" yaml:"id"`
	Config map[string]any `koanf:"config" yaml:"config"`
}
