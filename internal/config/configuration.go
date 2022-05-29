package config

import (
	"time"
)

const (
	defaultReadTimeout  = time.Second * 5
	defaultWriteTimeout = time.Second * 10
	defaultIdleTimeout  = time.Second * 120

	defaultProxyPort       = 4455
	defaultDecisionAPIPort = 4456
	defaultPrometheusPort  = 9000
)

type Configuration struct {
	Serve    ServeConfig    `koanf:"serve"`
	Log      LoggingConfig  `koanf:"log"`
	Tracing  TracingConfig  `koanf:"tracing"`
	Signer   SignerConfig   `koanf:"signer"`
	Cache    CacheConfig    `koanf:"cache"`
	Pipeline PipelineConfig `koanf:"pipeline"`
	Rules    RulesConfig    `koanf:"rules"`
}

func NewConfiguration(configFile string) (Configuration, error) {
	// copy defaults
	result := defaultConfig

	err := LoadConfig(&result, configFile)

	return result, err
}
