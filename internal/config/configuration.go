package config

import (
	"github.com/dadrus/heimdall/internal/logging"
)

type Configuration struct {
	Proxy       Serve      `koanf:"serve.proxy"`
	DecisionApi Serve      `koanf:"serve.api"`
	Prometheus  Prometheus `koanf:"serve.prometheus"`

	Log logging.LogConfig `koanf:"log"`

	Authenticators []PipelineObject `koanf:"authenticators"`
	Authorizers    []PipelineObject `koanf:"authorizers"`
	ErrorHandlers  []PipelineObject `koanf:"error_handlers"`
	Mutators       []PipelineObject `koanf:"mutators"`
	Hydrators      []PipelineObject `koanf:"hydrators"`

	DefaultPipeline struct {
		Authenticators []string `koanf:"authenticators"`
		Authorizer     string   `koanf:"authorizer"`
		ErrorHandlers  []string `koanf:"error_handlers"`
	} `koanf:"rule_defaults"`
}

func NewConfiguration(configFile string) Configuration {
	result := DefaultConfiguration
	err := LoadConfig(&result, configFile)
	if err != nil {
		panic(err)
	}
	return result
}

func LogConfiguration(configuration Configuration) logging.LogConfig {
	return configuration.Log
}
