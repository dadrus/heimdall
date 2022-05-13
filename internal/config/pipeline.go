package config

type PipelineConfig struct {
	Authenticators []PipelineObject `koanf:"authenticators"`
	Authorizers    []PipelineObject `koanf:"authorizers"`
	Hydrators      []PipelineObject `koanf:"hydrators"`
	Mutators       []PipelineObject `koanf:"mutators"`
	ErrorHandlers  []PipelineObject `koanf:"error_handlers"`
}
