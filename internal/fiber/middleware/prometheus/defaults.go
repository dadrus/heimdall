package prometheus

import (
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
)

// nolint: gochecknoglobals
var defaultOptions = opts{
	registrer:       prometheus.DefaultRegisterer,
	namespace:       "http",
	labels:          make(prometheus.Labels),
	filterOperation: func(ctx *fiber.Ctx) bool { return false },
}
