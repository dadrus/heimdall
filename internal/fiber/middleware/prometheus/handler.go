package prometheus

import (
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type metricsHandler struct {
	reqCounter      *prometheus.CounterVec
	reqHistogram    *prometheus.HistogramVec
	reqInFlight     *prometheus.GaugeVec
	filterOperation OperationFilter
}

func New(opts ...Option) fiber.Handler {
	options := defaultOptions

	for _, opt := range opts {
		opt(&options)
	}

	counter := promauto.With(options.registerer).NewCounterVec(
		prometheus.CounterOpts{
			Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "requests_total"),
			Help:        "Count all http requests by status code, method and path.",
			ConstLabels: options.labels,
		},
		[]string{"status_code", "method", "path"},
	)

	histogram := promauto.With(options.registerer).NewHistogramVec(prometheus.HistogramOpts{
		Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "request_duration_seconds"),
		Help:        "Duration of all HTTP requests by status code, method and path.",
		ConstLabels: options.labels,
		Buckets: []float64{
			0.000000001, // 1ns
			0.000000002,
			0.000000005,
			0.00000001, // 10ns
			0.00000002,
			0.00000005,
			0.0000001, // 100ns
			0.0000002,
			0.0000005,
			0.000001, // 1µs
			0.000002,
			0.000005,
			0.00001, // 10µs
			0.00002,
			0.00005,
			0.0001, // 100µs
			0.0002,
			0.0005,
			0.001, // 1ms
			0.002,
			0.005,
			0.01, // 10ms
			0.02,
			0.05,
			0.1, // 100 ms
			0.2,
			0.5,
			1.0, // 1s
			2.0,
			5.0,
			10.0, // 10s
			15.0,
			20.0,
			30.0,
		},
	},
		[]string{"status_code", "method", "path"},
	)

	gauge := promauto.With(options.registerer).NewGaugeVec(prometheus.GaugeOpts{
		Name:        prometheus.BuildFQName(options.namespace, options.subsystem, "requests_in_progress_total"),
		Help:        "All the requests in progress",
		ConstLabels: options.labels,
	}, []string{"method"})

	handler := &metricsHandler{
		reqCounter:      counter,
		reqHistogram:    histogram,
		reqInFlight:     gauge,
		filterOperation: options.filterOperation,
	}

	return handler.observeRequest
}

func (h *metricsHandler) observeRequest(ctx *fiber.Ctx) error {
	const magicNumber = 1e9

	start := time.Now()

	if h.filterOperation(ctx) {
		return ctx.Next()
	}

	method := ctx.Route().Method

	h.reqInFlight.WithLabelValues(method).Inc()

	defer func() {
		h.reqInFlight.WithLabelValues(method).Dec()
	}()

	err := ctx.Next()
	// initialize with default error code
	status := fiber.StatusInternalServerError

	if err != nil {
		var ferr *fiber.Error

		if errors.As(err, &ferr) {
			status = ferr.Code
		}
	} else {
		status = ctx.Response().StatusCode()
	}

	path := ctx.Route().Path
	statusCode := strconv.Itoa(status)
	h.reqCounter.WithLabelValues(statusCode, method, path).Inc()

	elapsed := float64(time.Since(start).Nanoseconds()) / magicNumber
	h.reqHistogram.WithLabelValues(statusCode, method, path).Observe(elapsed)

	return err
}
