package authorizers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthorizerTypeFactory(
		func(id string, typ config.PipelineObjectType, conf map[any]any) (bool, Authorizer, error) {
			if typ != config.POTRemote {
				return false, nil, nil
			}

			auth, err := newRemoteAuthorizer(id, conf)

			return true, auth, err
		})
}

type remoteAuthorizer struct {
	e                  endpoint.Endpoint
	name               string
	headers            map[string]template.Template
	payload            template.Template
	headersForUpstream []string
}

func newRemoteAuthorizer(name string, rawConfig map[any]any) (*remoteAuthorizer, error) {
	type _config struct {
		Endpoint                 endpoint.Endpoint            `mapstructure:"endpoint"`
		Headers                  map[string]template.Template `mapstructure:"headers"`
		Payload                  template.Template            `mapstructure:"payload"`
		ResponseHeadersToForward []string                     `mapstructure:"forward_response_headers_to_upstream"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal remote authorizer config").
			CausedBy(err)
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate endpoint configuration").
			CausedBy(err)
	}

	if len(conf.Headers) == 0 && len(conf.Payload) == 0 {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration,
				"either a payload or at least one header must be configured for remote authorizer")
	}

	if conf.Endpoint.Headers == nil {
		conf.Endpoint.Headers = make(map[string]string)
	}

	return &remoteAuthorizer{
		e:                  conf.Endpoint,
		name:               name,
		payload:            conf.Payload,
		headers:            conf.Headers,
		headersForUpstream: conf.ResponseHeadersToForward,
	}, nil
}

func (a *remoteAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using remote authorizer")

	req, err := a.createRequest(ctx, sub)
	if err != nil {
		return err
	}

	resp, err := a.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to the authorization endpoint timed out").CausedBy(err)
		}

		return errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to the authorization endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	authorizerResponse, err := a.readResponse(resp)
	if err != nil {
		return err
	}

	for _, headerName := range a.headersForUpstream {
		headerValue := resp.Header.Get(headerName)
		if len(headerValue) != 0 {
			ctx.AddResponseHeader(headerName, headerValue)
		}
	}

	if len(authorizerResponse) != 0 {
		sub.Attributes[a.name] = authorizerResponse
	}

	return nil
}

func (a *remoteAuthorizer) createRequest(ctx heimdall.Context, sub *subject.Subject) (*http.Request, error) {
	payload, err := a.createRequestPayload(ctx, sub)
	if err != nil {
		return nil, err
	}

	req, err := a.e.CreateRequest(ctx.AppContext(), payload)
	if err != nil {
		return nil, err
	}

	for headerName, headerTemplate := range a.headers {
		headerValue, err := headerTemplate.Render(ctx, sub)
		if err != nil {
			return nil, err
		}

		req.Header.Add(headerName, headerValue)
	}

	return req, nil
}

func (a *remoteAuthorizer) readResponse(resp *http.Response) (map[string]any, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if resp.ContentLength == 0 {
			return map[string]any{}, nil
		}

		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to read response").
				CausedBy(err)
		}

		var mapData map[string]any
		if err = json.Unmarshal(rawData, &mapData); err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal,
					"failed to unmarshal received response from hydration endpoint").
				CausedBy(err)
		}

		return mapData, nil
	}

	return nil, errorchain.
		NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode)
}

func (a *remoteAuthorizer) WithConfig(rawConfig map[any]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	type _config struct {
		Headers                  map[string]template.Template `mapstructure:"headers"`
		Payload                  template.Template            `mapstructure:"payload"`
		ResponseHeadersToForward []string                     `mapstructure:"forward_response_headers_to_upstream"`
	}

	var conf _config
	if err := mapstructure.Decode(rawConfig, &conf); err != nil {
		return nil, err
	}

	return &remoteAuthorizer{
		e:                  a.e,
		payload:            a.payload,
		headersForUpstream: conf.ResponseHeadersToForward,
	}, nil
}

func (a *remoteAuthorizer) createRequestPayload(ctx heimdall.Context, sub *subject.Subject) (io.Reader, error) {
	if a.payload == "original_body" {
		return bytes.NewReader(ctx.RequestBody()), nil
	}

	body, err := a.payload.Render(ctx, sub)
	if err != nil {
		return nil, err
	}

	return strings.NewReader(body), nil
}
