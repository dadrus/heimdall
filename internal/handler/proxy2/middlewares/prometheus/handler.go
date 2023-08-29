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
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func New(opts ...Option) func(http.Handler) http.Handler {
	options := defaultOptions

	for _, opt := range opts {
		opt(&options)
	}

	counter := promauto.With(options.registerer).NewCounterVec(
		prometheus.CounterOpts{
			Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "requests_total"),
			Help:        "Count all requests by status code, method and path.",
			ConstLabels: options.labels,
		},
		[]string{"http_code", "http_method", "http_path"},
	)

	histogram := promauto.With(options.registerer).NewHistogramVec(prometheus.HistogramOpts{
		Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "request_duration_seconds"),
		Help:        "Duration of all requests by status code, method and path.",
		ConstLabels: options.labels,
		Buckets: []float64{
			0.00001, 0.00005, // 10, 50µs
			0.0001, 0.00025, 0.0005, 0.00075, // 100, 250, 500, 750µs
			0.001, 0.0025, 0.005, 0.0075, // 1, 2.5, 5, 7.5ms
			0.01, 0.025, 0.05, 0.075, // 10, 25, 50, 75ms
			0.1, 0.25, 0.5, 0.75, // 100, 250, 500 750 ms
			1.0, 2.0, 5.0, // 1, 2, 5
		},
	},
		[]string{"http_code", "http_method", "http_path"},
	)

	gauge := promauto.With(options.registerer).NewGaugeVec(prometheus.GaugeOpts{
		Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "requests_in_progress_total"),
		Help:        "All the requests in progress",
		ConstLabels: options.labels,
	}, []string{"http_method"})

	return func(next http.Handler) http.Handler {
		const MagicNumber = 1e9

		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			start := time.Now()

			if options.filterOperation(req) {
				next.ServeHTTP(rw, req)

				return
			}

			gauge.WithLabelValues(req.Method).Inc()
			defer func() {
				gauge.WithLabelValues(req.Method).Dec()
			}()

			d := newDelegator(rw)
			next.ServeHTTP(d, req)

			statusCode := strconv.Itoa(d.Status())
			counter.WithLabelValues(statusCode, req.Method, req.URL.Path).Inc()

			elapsed := float64(time.Since(start).Nanoseconds()) / MagicNumber
			histogram.WithLabelValues(statusCode, req.Method, req.URL.Path).Observe(elapsed)
		})
	}
}
