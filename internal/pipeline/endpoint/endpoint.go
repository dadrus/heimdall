package endpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/opentracing-contrib/go-stdlib/nethttp"
	"github.com/rs/zerolog"
	"github.com/ybbus/httpretry"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/renderer"
	"github.com/dadrus/heimdall/internal/x"
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

type noopRenderer struct{}

func (noopRenderer) Render(value string) (string, error) { return value, nil }

func (e Endpoint) Validate() error {
	if len(e.URL) == 0 {
		return errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "endpoint requires url to be set")
	}

	return nil
}

func (e Endpoint) CreateClient(peerName string) *http.Client {
	client := &http.Client{
		Transport: &tracing.RoundTripper{Next: &nethttp.Transport{}, TargetName: peerName},
	}

	if e.Retry != nil {
		client = httpretry.NewCustomClient(
			client,
			httpretry.WithBackoffPolicy(
				httpretry.ExponentialBackoff(e.Retry.MaxDelay, e.Retry.GiveUpAfter, 0)))
	}

	return client
}

func (e Endpoint) CreateRequest(ctx context.Context, body io.Reader, rndr renderer.Renderer) (*http.Request, error) {
	logger := zerolog.Ctx(ctx)
	tpl := x.IfThenElse[renderer.Renderer](rndr != nil, rndr, noopRenderer{})

	method := "POST"
	if len(e.Method) != 0 {
		method = e.Method
	}

	endpointURL, err := tpl.Render(e.URL)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to render URL for the endpoint").CausedBy(err)
	}

	logger.Debug().Msgf("Creating request for %s", endpointURL)

	req, err := http.NewRequestWithContext(ctx, method, endpointURL, body)
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

	for headerName, valueTemplate := range e.Headers {
		headerValue, err := tpl.Render(valueTemplate)
		if err != nil {
			return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
				"failed to render %s header value", headerName).CausedBy(err)
		}

		req.Header.Set(headerName, headerValue)
	}

	return req, nil
}

func (e Endpoint) SendRequest(ctx context.Context, body io.Reader, renderer renderer.Renderer) ([]byte, error) {
	req, err := e.CreateRequest(ctx, body, renderer)
	if err != nil {
		return nil, err
	}

	resp, err := e.CreateClient(req.URL.Hostname()).Do(req)
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
		NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode)
}

func (e Endpoint) Hash() string {
	const int64BytesCount = 8

	hash := sha256.New()

	hash.Write([]byte(e.URL))
	hash.Write([]byte(e.Method))

	if e.Retry != nil {
		maxDelayBytes := make([]byte, int64BytesCount)
		binary.LittleEndian.PutUint64(maxDelayBytes, uint64(e.Retry.MaxDelay))

		giveUpAfterBytes := make([]byte, int64BytesCount)
		binary.LittleEndian.PutUint64(giveUpAfterBytes, uint64(e.Retry.GiveUpAfter))

		hash.Write(maxDelayBytes)
		hash.Write(giveUpAfterBytes)
	}

	buf := bytes.NewBufferString("")
	for k, v := range e.Headers {
		buf.Write([]byte(k))
		buf.Write([]byte(v))
	}

	hash.Write(buf.Bytes())

	if e.AuthStrategy != nil {
		hash.Write([]byte(e.AuthStrategy.Hash()))
	}

	return hex.EncodeToString(hash.Sum(nil))
}
