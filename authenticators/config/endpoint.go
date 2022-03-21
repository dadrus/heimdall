package config

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/dadrus/heimdall/authenticators/request_authentication_strategy"
	"github.com/dadrus/heimdall/x/httpx"
	"github.com/ybbus/httpretry"
)

type Endpoint struct {
	Url    *url.URL `json:"url"`
	Method string   `json:"method"`
	Retry  Retry    `json:"retry"`
	Auth   Auth     `json:"auth"`
}

type Retry struct {
	GiveUpAfter time.Duration `json:"give_up_after"`
	MaxDelay    time.Duration `json:"max_delay"`
}

type Auth struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

func (e Endpoint) Client() (*http.Client, error) {
	client := httpretry.NewCustomClient(
		&http.Client{
			Transport: &httpx.TracingRoundTripper{Next: http.DefaultTransport},
		},
		httpretry.WithBackoffPolicy(httpretry.ExponentialBackoff(e.Retry.MaxDelay, e.Retry.GiveUpAfter, 0)))
	return client, nil
}

func (e Endpoint) AuthenticationStrategy() (as request_authentication_strategy.AuthenticationStrategy, err error) {
	return request_authentication_strategy.NewAuthenticationStrategy(e.Auth.Type, e.Auth.Config)
}
