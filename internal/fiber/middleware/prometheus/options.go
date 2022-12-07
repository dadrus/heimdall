package prometheus

import (
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
)

type OperationFilter func(*fiber.Ctx) bool

type opts struct {
	registrer       prometheus.Registerer
	labels          prometheus.Labels
	namespace       string
	subsystem       string
	filterOperation OperationFilter
}

type Option func(*opts)

func WithRegisterer(registrer prometheus.Registerer) Option {
	return func(o *opts) {
		if registrer != nil {
			o.registrer = registrer
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
