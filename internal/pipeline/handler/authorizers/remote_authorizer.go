package authorizers

import (
	"bytes"

	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type remoteAuthorizer struct {
	Endpoint                 Endpoint
	Payload                  string
	ResponseHeadersToForward []string
}

func NewRemoteAuthorizer(rawConfig map[string]any) (*remoteAuthorizer, error) {
	return &remoteAuthorizer{}, nil
}

func (a *remoteAuthorizer) Authorize(ctx heimdall.Context, sub *subject.Subject) error {
	var payload []byte
	if a.Payload == "original_body" {
		payload = ctx.RequestBody()
	} else {
		// TODO: load template
	}

	_, err := a.Endpoint.SendRequest(ctx.AppContext(), bytes.NewReader(payload))
	if err != nil {
		return err
	}

	for range a.ResponseHeadersToForward {
		// TODO: get header hn from response and add it to the sc.Headers
	}

	return nil
}

func (a *remoteAuthorizer) WithConfig(rawConfig map[string]any) (handler.Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	type _config struct {
		ResponseHeadersToForward []string `mapstructure:"forward_response_headers"`
	}

	var conf _config
	if err := mapstructure.Decode(rawConfig, &conf); err != nil {
		return nil, err
	}

	return &remoteAuthorizer{
		Endpoint:                 a.Endpoint,
		Payload:                  a.Payload,
		ResponseHeadersToForward: conf.ResponseHeadersToForward,
	}, nil
}
