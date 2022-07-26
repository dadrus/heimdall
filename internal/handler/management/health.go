package management

import "github.com/gofiber/fiber/v2"

func health(c *fiber.Ctx) error {
	type status struct {
		Status string `json:"status"`
	}

	return c.JSON(status{Status: "ok"})
}
