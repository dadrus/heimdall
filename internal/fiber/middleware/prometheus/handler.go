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
			0.00001, 0.00005, // 10, 50µs
			0.0001, 0.00025, 0.0005, 0.00075, // 100, 250, 500, 750µs
			0.001, 0.0025, 0.005, 0.0075, // 1, 2.5, 5, 7.5ms
			0.01, 0.025, 0.05, 0.075, // 10, 25, 50, 75ms
			0.1, 0.25, 0.5, // 100, 250, 500 ms
			1.0, 2.0, 5.0, 10.0, 15.0, // 1, 2, 5, 10, 20s
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
