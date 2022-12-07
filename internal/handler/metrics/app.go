package metrics

import "github.com/gofiber/fiber/v2"

func newApp() *fiber.App {
	return fiber.New(fiber.Config{
		AppName:               "Heimdall's Prometheus endpoint",
		DisableStartupMessage: true,
	})
}
