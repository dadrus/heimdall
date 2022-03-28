package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/internal/x/httpx"
)

type Endpoint struct {
	Url     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Retry   *Retry            `yaml:"retry"`
	Auth    *Auth             `yaml:"auth"`
	Headers map[string]string `yaml:"headers"`
}

type Retry struct {
	GiveUpAfter time.Duration `yaml:"give_up_after"`
	MaxDelay    time.Duration `yaml:"max_delay"`
}

type Auth struct {
	Type   string          `yaml:"type"`
	Config json.RawMessage `yaml:"config"`
}

func (e Endpoint) Validate() error {
	if len(e.Url) == 0 {
		return errors.New("endpoint requires url to be set")
	}
	return nil
}

func (e Endpoint) SendRequest(ctx context.Context, body io.Reader) ([]byte, error) {
	client := httpretry.NewCustomClient(
		&http.Client{
			Transport: &httpx.TracingRoundTripper{Next: http.DefaultTransport},
		},
		httpretry.WithBackoffPolicy(httpretry.ExponentialBackoff(e.Retry.MaxDelay, e.Retry.GiveUpAfter, 0)))

	method := "POST"
	if len(e.Method) != 0 {
		method = e.Method
	}

	req, err := http.NewRequestWithContext(ctx, method, e.Url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	a, err := NewAuthenticationStrategy(e.Auth.Type, e.Auth.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication strategy: %w", err)
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
