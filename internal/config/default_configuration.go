package config

import (
	"time"

	"github.com/rs/zerolog"
)

const (
	defaultReadTimeout  = time.Second * 5
	defaultWriteTimeout = time.Second * 10
	defaultIdleTimeout  = time.Second * 120

	defaultProxyServicePort      = 4455
	defaultDecisionServicePort   = 4456
	defaultManagementServicePort = 4457
	defaultPrometheusServicePort = 10250
)

// nolint: gochecknoglobals
var defaultConfig = Configuration{
	Serve: ServeConfig{
		Proxy: ServiceConfig{
			Port: defaultProxyServicePort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
		Decision: ServiceConfig{
			Port: defaultDecisionServicePort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
		},
		Management: ServiceConfig{
			Port: defaultManagementServicePort,
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
		Enabled:           true,
		SpanProcessorType: SpanProcessorBatch,
	},
	Metrics: MetricsConfig{
		Prometheus: PrometheusConfig{
			Port:        defaultPrometheusServicePort,
			MetricsPath: "/metrics",
		},
	},
	Signer: SignerConfig{
		Name: "heimdall",
	},
}
