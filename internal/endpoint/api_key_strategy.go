package endpoint

import (
	"context"
	"crypto/sha256"
	"net/http"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type APIKeyStrategy struct {
	In    string `mapstructure:"in"`
	Name  string `mapstructure:"name"`
	Value string `mapstructure:"value"`
}

func (c *APIKeyStrategy) Apply(_ context.Context, req *http.Request) error {
	switch c.In {
	case "cookie":
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	case "header":
		req.Header.Set(c.Name, c.Value)
	default:
		return errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"unsupported in value (%s) in api key auth strategy", c.In)
	}

	return nil
}

func (c *APIKeyStrategy) Hash() []byte {
	hash := sha256.New()

	hash.Write([]byte(c.In))
	hash.Write([]byte(c.Name))
	hash.Write([]byte(c.Value))

	return hash.Sum(nil)
}
