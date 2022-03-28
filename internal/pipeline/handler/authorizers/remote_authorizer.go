package authorizers

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
)

type remoteAuthorizer struct {
	Endpoint                 Endpoint
	Payload                  string
	ResponseHeadersToForward []string
}

func NewRemoteAuthorizerFromJSON(rawConfig json.RawMessage) (*remoteAuthorizer, error) {
	return &remoteAuthorizer{}, nil
}

func (a *remoteAuthorizer) Authorize(ctx context.Context, sc *heimdall.SubjectContext) error {
	var payload string
	if a.Payload == "original_body" {
		// TODO: get original request body
	} else {
		// TODO: load template
	}

	_, err := a.Endpoint.SendRequest(ctx, strings.NewReader(payload))
	if err != nil {
		return err
	}

	for _, _ = range a.ResponseHeadersToForward {
		// TODO: get header hn from response and add it to the sc.Headers
	}

	return nil
}

func (a *remoteAuthorizer) WithConfig(config json.RawMessage) (handler.Authorizer, error) {
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		ResponseHeadersToForward []string `json:"forward_response_headers"`
	}

	var c _config
	if err := json.Unmarshal(config, &c); err != nil {
		return nil, err
	}

	return &remoteAuthorizer{
		Endpoint:                 a.Endpoint,
		Payload:                  a.Payload,
		ResponseHeadersToForward: c.ResponseHeadersToForward,
	}, nil
}
