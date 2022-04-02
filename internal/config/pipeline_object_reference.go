package config

type PipelineObjectReference struct {
	ID     string                 `koanf:"id" yaml:"id"`
	Config map[string]interface{} `koanf:"config" yaml:"config"`
}
