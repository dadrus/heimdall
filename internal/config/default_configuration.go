package config

import "github.com/rs/zerolog"

// nolint: gochecknoglobals
var defaultConfig = Configuration{
	Serve: ServeConfig{
		Proxy: ServiceConfig{
			Port: defaultProxyPort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
		DecisionAPI: ServiceConfig{
			Port: defaultDecisionAPIPort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
	},
	Log: LoggingConfig{
		Level:  zerolog.ErrorLevel,
		Format: LogTextFormat,
	},
	Tracing: TracingConfig{
		ServiceName: "heimdall",
	},
	Metrics: MetricsConfig{
		Prometheus: PrometheusConfig{
			Port:        defaultPrometheusPort,
			MetricsPath: "/metrics",
		},
	},
	Signer: SignerConfig{
		Name: "heimdall",
	},
	Pipeline: PipelineConfig{
		Authenticators: []PipelineObject{},
		Authorizers:    []PipelineObject{},
		Hydrators:      []PipelineObject{},
		Mutators:       []PipelineObject{},
		ErrorHandlers:  []PipelineObject{},
	},
}
