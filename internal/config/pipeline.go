package config

type Pipeline struct {
	Authenticators []PipelineObjectReference `koanf:"authenticators" yaml:"authenticators"`
	Authorizer     *PipelineObjectReference  `koanf:"authorizer" yaml:"authorizer"`
	Hydrators      []PipelineObjectReference `koanf:"hydrators" yaml:"hydrators"`
	Mutators       []PipelineObjectReference `koanf:"mutators" yaml:"mutators"`
	ErrorHandlers  []PipelineObjectReference `koanf:"error_handlers" yaml:"error_handlers"`
}
