package config

type Pipeline struct {
	Authenticators []PipelineObjectReference `koanf:"authenticators"`
	Authorizer     *PipelineObjectReference  `koanf:"authorizer"`
	Hydrators      []PipelineObjectReference `koanf:"hydrators"`
	Mutators       []PipelineObjectReference `koanf:"mutators"`
	ErrorHandlers  []PipelineObjectReference `koanf:"error_handlers"`
}
