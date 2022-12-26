package management

import (
	"github.com/gofiber/fiber/v2"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/heimdall"
)

// jwks implements an endpoint returning JWKS objects according to
// https://datatracker.ietf.org/doc/html/rfc7517
func jwks(signer heimdall.JWTSigner) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.JSON(jose.JSONWebKeySet{Keys: signer.Keys()})
	}
}
