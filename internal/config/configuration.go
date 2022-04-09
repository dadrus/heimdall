package config

import (
	"time"

	"github.com/rs/zerolog"
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
	Proxy       Serve      `koanf:"serve.proxy"`
	DecisionAPI Serve      `koanf:"serve.api"`
	Prometheus  Prometheus `koanf:"serve.prometheus"`
	Log         Logging    `koanf:"log"`
	Signer      *Signer    `koanf:"signer"`
	Pipeline    struct {
		Authenticators []PipelineObject `koanf:"authenticators"`
		Authorizers    []PipelineObject `koanf:"authorizers"`
		Hydrators      []PipelineObject `koanf:"hydrators"`
		Mutators       []PipelineObject `koanf:"mutators"`
		ErrorHandlers  []PipelineObject `koanf:"error_handlers"`
	} `koanf:"pipeline"`
	Rules struct {
		Default   Pipeline `koanf:"default"`
		Providers struct {
			File struct {
				Src   string `koanf:"src"`
				Watch bool   `koanf:"watch"`
			} `koanf:"file"`
		} `koanf:"providers"`
	} `koanf:"rules"`
}

func NewConfiguration(configFile string) Configuration {
	// defaults
	result := Configuration{
		Proxy: Serve{
			Port: defaultProxyPort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
		DecisionAPI: Serve{
			Port: defaultDecisionAPIPort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
		Prometheus: Prometheus{
			Port:        defaultPrometheusPort,
			MetricsPath: "/metrics",
		},
		Log: Logging{
			Level:             zerolog.DebugLevel,
			Format:            LogTextFormat,
			LeakSensitiveData: false,
		},
	}

	err := LoadConfig(&result, configFile)
	if err != nil {
		panic(err)
	}

	return result
}

func LogConfiguration(configuration Configuration) Logging {
	return configuration.Log
}
