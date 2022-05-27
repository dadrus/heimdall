package xforwarded

import (
	"context"
	"net/url"

	"github.com/gofiber/fiber/v2"

	"github.com/dadrus/heimdall/internal/x"
)

type (
	methodKey     struct{}
	requestURLKey struct{}
)

func New() fiber.Handler {
	return func(c *fiber.Ctx) error {
		method := requestMethod(c)
		reqURL := requestURL(c)

		ctx := context.WithValue(c.UserContext(), methodKey{}, method)
		ctx = context.WithValue(ctx, requestURLKey{}, reqURL)

		c.SetUserContext(ctx)

		return c.Next()
	}
}

// RequestMethod returns the HTTP method associated with the ctx. If no method is associated,
// an empty string is returned.
func RequestMethod(ctx context.Context) string {
	var (
		method string
		ok     bool
	)

	if val := ctx.Value(methodKey{}); val != nil {
		method, ok = val.(string)
	}

	return x.IfThenElse(ok, method, "")
}

// RequestURL returns the URL associated with the ctx. If no URL is associated,
// nil is returned.
func RequestURL(ctx context.Context) *url.URL {
	var (
		reqURL *url.URL
		ok     bool
	)

	if val := ctx.Value(requestURLKey{}); val != nil {
		reqURL, ok = val.(*url.URL)
	}

	return x.IfThenElse(ok, reqURL, nil)
}
