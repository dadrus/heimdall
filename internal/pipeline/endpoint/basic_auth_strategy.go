package endpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

type BasicAuthStrategy struct {
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

func (c *BasicAuthStrategy) Apply(_ context.Context, req *http.Request) error {
	req.SetBasicAuth(c.User, c.Password)

	return nil
}

func (c *BasicAuthStrategy) Hash() string {
	hash := sha256.New()

	hash.Write([]byte(c.User))
	hash.Write([]byte(c.Password))

	return hex.EncodeToString(hash.Sum(nil))
}
