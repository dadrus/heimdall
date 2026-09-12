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

	defaultRequestHeaderMaxSize = 64 * bytesize.KB
	defaultRequestBodyMaxSize   = 5 * bytesize.MB

	defaultRequestReadTimeout         = 0
	defaultRequestHeaderReadTimeout   = 5 * time.Second
	defaultRequestBodyReadIdleTimeout = 20 * time.Second
	defaultRequestBodyReadMinRate     = 0
	defaultResponseWriteTimeout       = 0
	defaultResponseWriteIdleTimeout   = 30 * time.Second
	defaultResponseWriteMinRate       = 0
	defaultConnectionIdleTimeout      = 2 * time.Minute

	defaultMaxConnections       = 1024
	defaultMaxInFlightRequests  = 512
	defaultMaxConcurrentStreams = 100

	defaultHTTP2ReadIdleTimeout = 30 * time.Second
	defaultHTTP2PingTimeout     = 15 * time.Second

	defaultUpstreamMaxConnectionsPerHost = 100
	defaultUpstreamMaxIdleConnections    = 100
	defaultUpstreamMaxIdlePerHost        = 100

	defaultUpstreamDialTimeout           = 5 * time.Second
	defaultUpstreamTLSHandshakeTimeout   = 10 * time.Second
	defaultUpstreamIdleTimeout           = 90 * time.Second
	defaultUpstreamExpectContinueTimeout = time.Second
	defaultUpstreamWriteIdleTimeout      = 30 * time.Second

	defaultUpstreamResponseHeaderMaxSize     = bytesize.MB
	defaultUpstreamResponseHeaderReadTimeout = 30 * time.Second

	defaultUpstreamHTTP2ReadIdleTimeout = 30 * time.Second
	defaultUpstreamHTTP2PingTimeout     = 15 * time.Second

	defaultServePort             = 4456
	defaultManagementServicePort = 4457
	defaultProfilingServicePort  = 10251

	loopbackIP = "127.0.0.1"
)

//nolint:funlen
func defaultConfig() Configuration {
	return Configuration{
		Serve: ServeConfig{
			Port: defaultServePort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
			Requests: IngressRequests{
				MaxInFlight: defaultMaxInFlightRequests,
				ReadTimeout: defaultRequestReadTimeout,
				Headers: IngressRequestHeaders{
					MaxSize:     defaultRequestHeaderMaxSize,
					ReadTimeout: defaultRequestHeaderReadTimeout,
				},
				Body: IngressRequestBody{
					MaxSize:         defaultRequestBodyMaxSize,
					ReadIdleTimeout: defaultRequestBodyReadIdleTimeout,
					ReadMinRate:     defaultRequestBodyReadMinRate,
				},
			},
			Responses: IngressResponses{
				WriteTimeout:     defaultResponseWriteTimeout,
				WriteIdleTimeout: defaultResponseWriteIdleTimeout,
				WriteMinRate:     defaultResponseWriteMinRate,
			},
			Connections: IngressConnections{
				Max:         defaultMaxConnections,
				IdleTimeout: defaultConnectionIdleTimeout,
			},
			HTTP2: IngressHTTP2{
				MaxConcurrentStreams: defaultMaxConcurrentStreams,
				ReadIdleTimeout:      defaultHTTP2ReadIdleTimeout,
				PingTimeout:          defaultHTTP2PingTimeout,
			},
			Upstream: UpstreamConfig{
				Connections: UpstreamConnections{
					MaxPerHost:          defaultUpstreamMaxConnectionsPerHost,
					MaxIdle:             defaultUpstreamMaxIdleConnections,
					MaxIdlePerHost:      defaultUpstreamMaxIdlePerHost,
					DialTimeout:         defaultUpstreamDialTimeout,
					TLSHandshakeTimeout: defaultUpstreamTLSHandshakeTimeout,
					IdleTimeout:         defaultUpstreamIdleTimeout,
				},
				Requests: UpstreamRequests{
					ExpectContinueTimeout: defaultUpstreamExpectContinueTimeout,
					WriteIdleTimeout:      defaultUpstreamWriteIdleTimeout,
				},
				Responses: UpstreamResponses{
					Headers: UpstreamResponseHeaders{
						MaxSize:     defaultUpstreamResponseHeaderMaxSize,
						ReadTimeout: defaultUpstreamResponseHeaderReadTimeout,
					},
				},
				HTTP2: UpstreamHTTP2{
					ReadIdleTimeout: defaultUpstreamHTTP2ReadIdleTimeout,
					PingTimeout:     defaultUpstreamHTTP2PingTimeout,
				},
			},
		},
		Management: ManagementConfig{
			Port: defaultManagementServicePort,
			Timeout: Timeout{
				Read:  defaultReadTimeout,
				Write: defaultWriteTimeout,
				Idle:  defaultIdleTimeout,
			},
			Requests: IngressRequests{
				MaxInFlight: defaultMaxInFlightRequests,
				ReadTimeout: defaultRequestReadTimeout,
				Headers: IngressRequestHeaders{
					MaxSize:     defaultRequestHeaderMaxSize,
					ReadTimeout: defaultRequestHeaderReadTimeout,
				},
				Body: IngressRequestBody{
					MaxSize:         defaultRequestBodyMaxSize,
					ReadIdleTimeout: defaultRequestBodyReadIdleTimeout,
					ReadMinRate:     defaultRequestBodyReadMinRate,
				},
			},
			Responses: IngressResponses{
				WriteTimeout:     defaultResponseWriteTimeout,
				WriteIdleTimeout: defaultResponseWriteIdleTimeout,
				WriteMinRate:     defaultResponseWriteMinRate,
			},
			Connections: IngressConnections{
				Max:         defaultMaxConnections,
				IdleTimeout: defaultConnectionIdleTimeout,
			},
		},
		Cache: CacheConfig{
			Type:   "in-memory",
			Config: map[string]any{},
		},
		Log: LoggingConfig{
			Level:            zerolog.ErrorLevel,
			Format:           LogTextFormat,
			AccessLogEnabled: true,
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
		Catalogue: &MechanismCatalogue{},
	}
}
