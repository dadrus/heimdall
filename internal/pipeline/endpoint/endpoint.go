package endpoint

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/tracing"
)

type Endpoint struct {
	URL          string                 `mapstructure:"url"`
	Method       string                 `mapstructure:"method"`
	Retry        *Retry                 `mapstructure:"retry"`
	AuthStrategy AuthenticationStrategy `mapstructure:"auth"`
	Headers      map[string]string      `mapstructure:"headers"`
}

type Retry struct {
	GiveUpAfter time.Duration `mapstructure:"give_up_after"`
	MaxDelay    time.Duration `mapstructure:"max_delay"`
}

type Auth struct {
	Type   string                 `mapstructure:"type"`
	Config map[string]interface{} `mapstructure:"config"`
}

func (e Endpoint) Validate() error {
	if len(e.URL) == 0 {
		return errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "endpoint requires url to be set")
	}

	return nil
}

func (e Endpoint) CreateClient() *http.Client {
	client := &http.Client{
		Transport: &tracing.RoundTripper{Next: http.DefaultTransport},
	}

	if e.Retry != nil {
		client = httpretry.NewCustomClient(
			client,
			httpretry.WithBackoffPolicy(
				httpretry.ExponentialBackoff(e.Retry.MaxDelay, e.Retry.GiveUpAfter, 0)))
	}

	return client
}

func (e Endpoint) CreateRequest(ctx context.Context, body io.Reader) (*http.Request, error) {
	logger := zerolog.Ctx(ctx)

	method := "POST"
	if len(e.Method) != 0 {
		method = e.Method
	}

	logger.Debug().Msgf("Creating request for %s", e.URL)

	req, err := http.NewRequestWithContext(ctx, method, e.URL, body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to create request").
			CausedBy(err)
	}

	if e.AuthStrategy != nil {
		logger.Debug().Msgf("Authenticating request for %s", e.URL)

		err = e.AuthStrategy.Apply(ctx, req)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to authenticate request").
				CausedBy(err)
		}
	}

	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

func (e Endpoint) SendRequest(ctx context.Context, body io.Reader) ([]byte, error) {
	req, err := e.CreateRequest(ctx, body)
	if err != nil {
		return nil, err
	}

	resp, err := e.CreateClient().Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.New(heimdall.ErrCommunicationTimeout).CausedBy(err)
		}

		return nil, errorchain.New(heimdall.ErrCommunication).CausedBy(err)
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
		NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode)
}
