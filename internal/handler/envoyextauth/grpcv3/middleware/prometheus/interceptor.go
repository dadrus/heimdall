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
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type ServerInterceptor interface {
	Unary() grpc.UnaryServerInterceptor
	Stream() grpc.StreamServerInterceptor
}

type metricsHandler struct {
	reqCounter   *prometheus.CounterVec
	reqHistogram *prometheus.HistogramVec
	reqInFlight  *prometheus.GaugeVec
}

func (h *metricsHandler) Unary() grpc.UnaryServerInterceptor   { return h.observeUnaryRequest }
func (h *metricsHandler) Stream() grpc.StreamServerInterceptor { return h.observeStreamRequest }

func New(opts ...Option) ServerInterceptor {
	options := defaultOptions

	for _, opt := range opts {
		opt(&options)
	}

	counter := promauto.With(options.registerer).NewCounterVec(
		prometheus.CounterOpts{
			Name: prometheus.BuildFQName(options.namespace, options.subsystem, "requests_total"),
			Help: "Count all requests by tunneled HTTP status code, service and method, as well as by" +
				" GRPC method and status code.",
			ConstLabels: options.labels,
		},
		[]string{"http_code", "http_method", "http_path", "grpc_method", "grpc_code"},
	)

	histogram := promauto.With(options.registerer).NewHistogramVec(prometheus.HistogramOpts{
		Name: prometheus.BuildFQName(options.namespace, options.subsystem, "request_duration_seconds"),
		Help: "Duration of all requests by tunneled HTTP status code, service and method, as well as by" +
			" GRPC method and status code.",
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
		[]string{"http_code", "http_method", "http_path", "grpc_method", "grpc_code"},
	)

	gauge := promauto.With(options.registerer).NewGaugeVec(prometheus.GaugeOpts{
		Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "requests_in_progress_total"),
		Help:        "All the requests in progress by tunneled HTTP method, as well as by GRPC method.",
		ConstLabels: options.labels,
	}, []string{"http_method", "grpc_method"})

	handler := &metricsHandler{
		reqCounter:   counter,
		reqHistogram: histogram,
		reqInFlight:  gauge,
	}

	return handler
}

func (h *metricsHandler) observeUnaryRequest(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	const (
		MagicNumber = 1e9
		Unknown     = "unknown"
	)

	start := time.Now()
	grpcMethod := info.FullMethod
	grpcCode := "0"
	httpMethod := Unknown
	httpPath := Unknown
	httpCode := Unknown

	if cr, ok := req.(*envoy_auth.CheckRequest); ok {
		httpMethod = cr.Attributes.Request.Http.Method
		httpPath = cr.Attributes.Request.Http.Path
	}

	h.reqInFlight.WithLabelValues(httpMethod, grpcMethod).Inc()

	defer func() {
		h.reqInFlight.WithLabelValues(httpMethod, grpcMethod).Dec()
	}()

	resp, err := handler(ctx, req)

	if err != nil {
		s, _ := status.FromError(err)
		grpcCode = strconv.Itoa(int(s.Code()))
	} else if cr, ok := resp.(*envoy_auth.CheckResponse); ok {
		httpCode = strconv.Itoa(int(cr.Status.Code))
	}

	h.reqCounter.WithLabelValues(httpCode, httpMethod, httpPath, grpcMethod, grpcCode).Inc()

	elapsed := float64(time.Since(start).Nanoseconds()) / MagicNumber
	h.reqHistogram.WithLabelValues(httpCode, httpMethod, httpPath, grpcMethod, grpcCode).Observe(elapsed)

	return resp, err
}

func (h *metricsHandler) observeStreamRequest(
	srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	const (
		MagicNumber = 1e9
		Unknown     = "unknown"
	)

	start := time.Now()
	grpcMethod := info.FullMethod
	grpcCode := "0"
	httpMethod := Unknown
	httpPath := Unknown
	httpCode := Unknown

	h.reqInFlight.WithLabelValues(httpMethod, grpcMethod).Inc()

	defer func() {
		h.reqInFlight.WithLabelValues(httpMethod, grpcMethod).Dec()
	}()

	err := handler(srv, stream)

	if err != nil {
		s, _ := status.FromError(err)
		grpcCode = strconv.Itoa(int(s.Code()))
	}

	h.reqCounter.WithLabelValues(httpCode, httpMethod, httpPath, grpcMethod, grpcCode).Inc()

	elapsed := float64(time.Since(start).Nanoseconds()) / MagicNumber
	h.reqHistogram.WithLabelValues(httpCode, httpMethod, httpPath, grpcMethod, grpcCode).Observe(elapsed)

	return err
}
