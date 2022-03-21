package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/dadrus/heimdall/authenticators/request_authentication_strategy"
	"github.com/dadrus/heimdall/x/httpx"
	"github.com/ybbus/httpretry"
)

type Endpoint struct {
	Url     *url.URL          `json:"url"`
	Method  string            `json:"method"`
	Retry   Retry             `json:"retry"`
	Auth    Auth              `json:"auth"`
	Headers map[string]string `json:"headers"`
}

type Retry struct {
	GiveUpAfter time.Duration `json:"give_up_after"`
	MaxDelay    time.Duration `json:"max_delay"`
}

type Auth struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

func (e Endpoint) SendRequest(ctx context.Context, body io.Reader) ([]byte, error) {
	client := httpretry.NewCustomClient(
		&http.Client{
			Transport: &httpx.TracingRoundTripper{Next: http.DefaultTransport},
		},
		httpretry.WithBackoffPolicy(httpretry.ExponentialBackoff(e.Retry.MaxDelay, e.Retry.GiveUpAfter, 0)))

	req, err := http.NewRequestWithContext(ctx, e.Method, e.Url.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	a, err := request_authentication_strategy.NewAuthenticationStrategy(e.Auth.Type, e.Auth.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate request: %w", err)
	}

	err = a.Apply(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate request: %w", err)
	}

	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	return e.readResponse(resp)
}

func (e Endpoint) readResponse(resp *http.Response) ([]byte, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		return rawData, nil
	} else {
		return nil, errors.New(fmt.Sprintf("unexpected response. code: %v", resp.StatusCode))
	}
}
