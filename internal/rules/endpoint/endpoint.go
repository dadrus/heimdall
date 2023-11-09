// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package endpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
	"github.com/ybbus/httpretry"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/httpcache"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/httpx"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

type Endpoint struct {
	URL              string                 `mapstructure:"url"               validate:"required,url"`
	Method           string                 `mapstructure:"method"`
	Retry            *Retry                 `mapstructure:"retry"`
	AuthStrategy     AuthenticationStrategy `mapstructure:"auth"`
	Headers          map[string]string      `mapstructure:"headers"`
	HTTPCacheEnabled *bool                  `mapstructure:"enable_http_cache"`
}

type Retry struct {
	GiveUpAfter time.Duration `mapstructure:"give_up_after"`
	MaxDelay    time.Duration `mapstructure:"max_delay"`
}

func (e Endpoint) CreateClient(peerName string) *http.Client {
	client := &http.Client{
		Transport: otelhttp.NewTransport(
			httpx.NewTraceRoundTripper(http.DefaultTransport),
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return fmt.Sprintf("%s %s %s @%s", r.Proto, r.Method, r.URL.Path, peerName)
			})),
	}

	if e.Retry != nil {
		client = httpretry.NewCustomClient(
			client,
			httpretry.WithBackoffPolicy(
				httpretry.ExponentialBackoff(e.Retry.MaxDelay, e.Retry.GiveUpAfter, 0)))
	}

	if e.HTTPCacheEnabled != nil && *e.HTTPCacheEnabled {
		client.Transport = &httpcache.RoundTripper{Transport: client.Transport}
	}

	return client
}

func (e Endpoint) CreateRequest(ctx context.Context, body io.Reader, rndr Renderer) (*http.Request, error) {
	logger := zerolog.Ctx(ctx)
	tpl := x.IfThenElse[Renderer](rndr != nil, rndr, noopRenderer{})

	method := http.MethodPost
	if len(e.Method) != 0 {
		method = e.Method
	}

	endpointURL, err := tpl.Render(e.URL)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to render URL for the endpoint").CausedBy(err)
	}

	logger.Debug().Str("_endpoint", endpointURL).Msg("Creating request")

	req, err := http.NewRequestWithContext(ctx, method, endpointURL, body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to create a request instance").
			CausedBy(err)
	}

	if e.AuthStrategy != nil {
		logger.Debug().Msg("Authenticating request")

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

type ResponseReader func(resp *http.Response) ([]byte, error)

func (e Endpoint) SendRequest(
	ctx context.Context,
	body io.Reader,
	renderer Renderer,
	reader ...ResponseReader,
) ([]byte, error) {
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

	defer resp.Body.Close()

	if len(reader) != 0 {
		return reader[0](resp)
	}

	return e.readResponse(resp)
}

func (e Endpoint) readResponse(resp *http.Response) ([]byte, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := io.ReadAll(resp.Body)
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

func (e Endpoint) Hash() []byte {
	const int64BytesCount = 8

	hash := sha256.New()

	hash.Write(stringx.ToBytes(e.URL))
	hash.Write(stringx.ToBytes(e.Method))

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
		buf.Write(stringx.ToBytes(k))
		buf.Write(stringx.ToBytes(v))
	}

	hash.Write(buf.Bytes())

	if e.AuthStrategy != nil {
		hash.Write(e.AuthStrategy.Hash())
	}

	return hash.Sum(nil)
}
