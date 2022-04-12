package config

type RuleConfig struct {
	ID               string   `yaml:"id"`
	URL              string   `yaml:"url"`
	MatchingStrategy string   `yaml:"matching_strategy"`
	Methods          []string `yaml:"methods"`

	Authenticators []PipelineObjectReference `yaml:"authenticators"`
	Authorizer     *PipelineObjectReference  `yaml:"authorizer"`
	Hydrators      []PipelineObjectReference `yaml:"hydrators"`
	Mutators       []PipelineObjectReference `yaml:"mutators"`
	ErrorHandlers  []PipelineObjectReference `yaml:"error_handlers"`
}
