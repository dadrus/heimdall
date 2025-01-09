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

	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog"
)

const (
	defaultReadTimeout  = time.Second * 5
	defaultWriteTimeout = time.Second * 10
	defaultIdleTimeout  = time.Second * 120

	defaultMaxIdleConnections        = 100
	defaultMaxIdleConnectionsPerHost = 100

	defaultServePort             = 4455
	defaultManagementServicePort = 4457
	defaultProfilingServicePort  = 10251

	defaultBufferSize = 4 * bytesize.KB

	loopbackIP = "127.0.0.1"
)

func defaultConfig() Configuration {
	return Configuration{
		Serve: ServeConfig{
			Port: defaultServePort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
			BufferLimit: BufferLimit{
				Read:  defaultBufferSize,
				Write: defaultBufferSize,
			},
			ConnectionsLimit: ConnectionsLimit{
				MaxIdle:        defaultMaxIdleConnections,
				MaxIdlePerHost: defaultMaxIdleConnectionsPerHost,
			},
		},
		Management: ManagementConfig{
			Port: defaultManagementServicePort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
			BufferLimit: BufferLimit{
				Read:  defaultBufferSize,
				Write: defaultBufferSize,
			},
		},
		Cache: CacheConfig{
			Type:   "in-memory",
			Config: map[string]any{},
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
			Enabled: true,
		},
		Profiling: ProfilingConfig{
			Enabled: false,
			Port:    defaultProfilingServicePort,
			Host:    loopbackIP,
		},
		Prototypes: &MechanismPrototypes{},
	}
}
