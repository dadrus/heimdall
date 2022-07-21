package management

import (
	"github.com/gofiber/fiber/v2"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/keystore"
)

const EndpointJWKS = "/.well-known/jwks"

// jwks implements an endpoint returning JWKS objects according to
// https://datatracker.ietf.org/doc/html/rfc7517
func jwks(ks keystore.KeyStore) fiber.Handler {
	// As of today, key store configuration is part of static configuration. So key store can not be updated
	// without a new heimdall deployment. For this reason the conversion is done here. Should the support for
	// dynamic key store updates be added in the future, the lines below, will have to be moved into the handler
	// implementation.
	entries := ks.Entries()
	keys := make([]jose.JSONWebKey, len(entries))

	for idx, entry := range entries {
		keys[idx] = entry.JWK()
	}

	return func(c *fiber.Ctx) error {
		return c.JSON(jose.JSONWebKeySet{Keys: keys})
	}
}
