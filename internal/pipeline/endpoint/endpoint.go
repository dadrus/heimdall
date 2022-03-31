package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
)

type Endpoint struct {
	URL     string            `yaml:"url"`
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
	if len(e.URL) == 0 {
		return errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "endpoint requires url to be set")
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

	req, err := http.NewRequestWithContext(ctx, method, e.URL, body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to create request").
			CausedBy(err)
	}

	authStrategy, err := NewAuthenticationStrategy(e.Auth.Type, e.Auth.Config)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to create authentication strategy").
			CausedBy(err)
	}

	err = authStrategy.Apply(ctx, req)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to authenticate request").
			CausedBy(err)
	}

	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.New(heimdall.ErrCommunicationTimeout).
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "failed to send request").
			CausedBy(err)
	}

	return e.readResponse(resp)
}

func (e Endpoint) readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to read response").
				CausedBy(err)
		}

		return rawData, nil
	}

	return nil, errorchain.
		NewWithMessagef(heimdall.ErrInternal, "unexpected response. code: %v", resp.StatusCode)
}
