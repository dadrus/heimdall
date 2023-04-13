// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	defaultMetricsServicePort    = 10250
	defaultProfilingServicePort  = 10251

	loopbackIP = "127.0.0.1"
)

func defaultConfig() Configuration {
	return Configuration{
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
			Enabled:     true,
			Port:        defaultMetricsServicePort,
			Host:        loopbackIP,
			MetricsPath: "/metrics",
		},
		Profiling: ProfilingConfig{
			Enabled: false,
			Port:    defaultProfilingServicePort,
			Host:    loopbackIP,
		},
		Signer: SignerConfig{
			Name: "heimdall",
		},
		Rules: Rules{
			Prototypes: &MechanismPrototypes{},
		},
	}
}
