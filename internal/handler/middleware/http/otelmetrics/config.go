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

package otelmetrics

import (
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const serviceSubsystemKey = attribute.Key("service.subsystem")

type OperationFilter func(req *http.Request) bool

type config struct {
	server        string
	subsystem     attribute.KeyValue
	provider      metric.MeterProvider
	attributes    []attribute.KeyValue
	shouldProcess OperationFilter
}

type Option func(*config)

func WithMeterProvider(provider metric.MeterProvider) Option {
	return func(o *config) {
		if provider != nil {
			o.provider = provider
		}
	}
}

func WithAttributes(kv ...attribute.KeyValue) Option {
	return func(o *config) {
		o.attributes = append(o.attributes, kv...)
	}
}

func WithOperationFilter(filter OperationFilter) Option {
	return func(o *config) {
		if filter != nil {
			o.shouldProcess = filter
		}
	}
}

func WithServerName(name string) Option {
	return func(o *config) {
		if len(name) != 0 {
			o.server = name
		}
	}
}

func WithSubsystem(name string) Option {
	return func(o *config) {
		if len(name) != 0 {
			o.subsystem = serviceSubsystemKey.String(name)
		}
	}
}

func newConfig(opts ...Option) *config {
	conf := config{
		provider:      otel.GetMeterProvider(),
		shouldProcess: func(_ *http.Request) bool { return true },
	}

	for _, opt := range opts {
		opt(&conf)
	}

	return &conf
}
