package config

type PipelineHandlersConfig struct {
	Authenticators []PipelineHandler `koanf:"authenticators"`
	Authorizers    []PipelineHandler `koanf:"authorizers"`
	Hydrators      []PipelineHandler `koanf:"hydrators"`
	Mutators       []PipelineHandler `koanf:"mutators"`
	ErrorHandlers  []PipelineHandler `koanf:"error_handlers"`
}
