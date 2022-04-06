package authorizers

import (
	"bytes"
	"errors"
	"net/url"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func init() {
	handler.RegisterAuthorizerTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, handler.Authorizer, error) {
			if typ != config.POTRemote {
				return false, nil, nil
			}

			auth, err := newRemoteAuthorizer(conf)

			return true, auth, err
		})
}

type remoteAuthorizer struct {
	e    Endpoint
	p    string
	rhtf []string
}

func newRemoteAuthorizer(rawConfig map[string]any) (*remoteAuthorizer, error) {
	return &remoteAuthorizer{}, nil
}

func (a *remoteAuthorizer) Authorize(ctx heimdall.Context, sub *subject.Subject) error {
	payload, err := a.createRequestPayload(ctx, sub)
	if err != nil {
		return err
	}

	req, err := a.e.CreateRequest(ctx.AppContext(), bytes.NewReader(payload))
	if err != nil {
		return err
	}

	resp, err := a.e.CreateClient().Do(req)
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

	for _, headerName := range a.rhtf {
		headerValue := resp.Header.Get(headerName)
		if len(headerValue) != 0 {
			ctx.AddResponseHeader(headerName, headerValue)
		}
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
		e:    a.e,
		p:    a.p,
		rhtf: conf.ResponseHeadersToForward,
	}, nil
}

func (a *remoteAuthorizer) createRequestPayload(ctx heimdall.Context, sub *subject.Subject) ([]byte, error) {
	if a.p == "original_body" {
		return ctx.RequestBody(), nil
	}

	return a.executeTemplate(sub)
}

func (a *remoteAuthorizer) executeTemplate(sub *subject.Subject) ([]byte, error) {
	return nil, nil
}
