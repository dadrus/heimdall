// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package prometheus

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

type OperationFilter func(req *http.Request) bool

type opts struct {
	registerer      prometheus.Registerer
	labels          prometheus.Labels
	namespace       string
	subsystem       string
	filterOperation OperationFilter
}

type Option func(*opts)

func WithRegisterer(registerer prometheus.Registerer) Option {
	return func(o *opts) {
		if registerer != nil {
			o.registerer = registerer
		}
	}
}

func WithServiceName(name string) Option {
	return func(o *opts) {
		if len(name) != 0 {
			o.labels["service"] = name
		}
	}
}

func WithNamespace(name string) Option {
	return func(o *opts) {
		if len(name) != 0 {
			o.namespace = name
		}
	}
}

func WithSubsystem(name string) Option {
	return func(o *opts) {
		if len(name) != 0 {
			o.subsystem = name
		}
	}
}

func WithLabel(label, value string) Option {
	return func(o *opts) {
		if len(label) != 0 && len(value) != 0 {
			o.labels[label] = value
		}
	}
}

func WithLabels(labels map[string]string) Option {
	return func(o *opts) {
		for label, value := range labels {
			if len(label) != 0 && len(value) != 0 {
				o.labels[label] = value
			}
		}
	}
}

func WithOperationFilter(filter OperationFilter) Option {
	return func(o *opts) {
		if filter != nil {
			o.filterOperation = filter
		}
	}
}
