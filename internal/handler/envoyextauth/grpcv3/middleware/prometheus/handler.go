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

package prometheus

import (
    "context"
    "strconv"
    "strings"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

type metricsHandler struct {
    reqCounter   *prometheus.CounterVec
    reqHistogram *prometheus.HistogramVec
    reqInFlight  *prometheus.GaugeVec
}

func New(opts ...Option) grpc.UnaryServerInterceptor {
    options := defaultOptions

    for _, opt := range opts {
        opt(&options)
    }

    counter := promauto.With(options.registerer).NewCounterVec(
        prometheus.CounterOpts{
            Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "requests_total"),
            Help:        "Count all grpc requests by status code, service and method.",
            ConstLabels: options.labels,
        },
        []string{"grpc_code", "grpc_service", "grpc_method"},
    )

    histogram := promauto.With(options.registerer).NewHistogramVec(prometheus.HistogramOpts{
        Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "request_duration_seconds"),
        Help:        "Duration of all grpc requests by code, service and method.",
        ConstLabels: options.labels,
        Buckets: []float64{
            0.00001, 0.000025, 0.00005, 0.000075, // 10, 25, 50, 75µs
            0.0001, 0.00025, 0.0005, 0.00075, // 100, 250, 500, 750µs
            0.001, 0.0025, 0.005, 0.0075, // 1, 2.5, 5, 7.5ms
            0.01, 0.025, 0.05, 0.075, // 10, 25, 50, 75ms
            0.1, 0.25, 0.5, 0.75, // 100, 250, 500 750ms
            1.0, 2.0, // 1, 2s
        },
    },
        []string{"grpc_code", "grpc_service", "grpc_method"},
    )

    gauge := promauto.With(options.registerer).NewGaugeVec(prometheus.GaugeOpts{
        Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "requests_in_progress_total"),
        Help:        "All the requests in progress",
        ConstLabels: options.labels,
    }, []string{"grpc_service", "grpc_method"})

    handler := &metricsHandler{
        reqCounter:   counter,
        reqHistogram: histogram,
        reqInFlight:  gauge,
    }

    return handler.observeRequest
}

func (h *metricsHandler) observeRequest(
    ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
    const MagicNumber = 1e9

    start := time.Now()
    serviceName, methodName := splitMethodName(info.FullMethod)

    h.reqInFlight.WithLabelValues(serviceName, methodName).Inc()

    defer func() {
        h.reqInFlight.WithLabelValues(serviceName, methodName).Dec()
    }()

    resp, err := handler(ctx, req)
    // initialize with default error code
    code := codes.Internal

    if err != nil {
        s, _ := status.FromError(err)
        code = s.Code()
    } else {
        code = codes.OK
    }

    statusCode := strconv.Itoa(int(code))
    h.reqCounter.WithLabelValues(statusCode, serviceName, methodName).Inc()

    elapsed := float64(time.Since(start).Nanoseconds()) / MagicNumber
    h.reqHistogram.WithLabelValues(statusCode, serviceName, methodName).Observe(elapsed)

    return resp, err
}

func splitMethodName(fullMethodName string) (string, string) {
    fullMethodName = strings.TrimPrefix(fullMethodName, "/") // remove leading slash
    if i := strings.Index(fullMethodName, "/"); i >= 0 {
        return fullMethodName[:i], fullMethodName[i+1:]
    }
    return "unknown", "unknown"
}
