package authorizers

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
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
	ttl                *time.Duration
}

type authorizationInformation struct {
	header  http.Header
	payload map[string]any
}

func newRemoteAuthorizer(name string, rawConfig map[any]any) (*remoteAuthorizer, error) {
	type _config struct {
		Endpoint                 endpoint.Endpoint            `mapstructure:"endpoint"`
		Headers                  map[string]template.Template `mapstructure:"headers"`
		Payload                  template.Template            `mapstructure:"payload"`
		ResponseHeadersToForward []string                     `mapstructure:"forward_response_headers_to_upstream"`
		CacheTTL                 *time.Duration               `mapstructure:"cache_ttl"`
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
		ttl:                conf.CacheTTL,
	}, nil
}

func (a *remoteAuthorizer) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authorizing using remote authorizer")

	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheKey string
		authInfo *authorizationInformation
		err      error
	)

	if a.ttl != nil {
		cacheKey = a.calculateCacheKey(sub)
		if item := cch.Get(cacheKey); item != nil {
			if cachedResponse, ok := item.(*authorizationInformation); !ok {
				logger.Warn().Msg("Wrong object type from cache")
				cch.Delete(cacheKey)
			} else {
				logger.Debug().Msg("Reusing introspection response from cache")

				authInfo = cachedResponse
			}
		}
	}

	if authInfo == nil {
		authInfo, err = a.doAuthorize(ctx, sub)
		if err != nil {
			return err
		}

		if a.ttl != nil {
			cch.Set(cacheKey, authInfo, *a.ttl)
		}
	}

	for _, headerName := range a.headersForUpstream {
		headerValue := authInfo.header.Get(headerName)
		if len(headerValue) != 0 {
			ctx.AddResponseHeader(headerName, headerValue)
		}
	}

	if len(authInfo.payload) != 0 {
		sub.Attributes[a.name] = authInfo.payload
	}

	return nil
}

func (a *remoteAuthorizer) doAuthorize(ctx heimdall.Context, sub *subject.Subject) (*authorizationInformation, error) {
	req, err := a.createRequest(ctx, sub)
	if err != nil {
		return nil, err
	}

	resp, err := a.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to the authorization endpoint timed out").CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to the authorization endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	data, err := a.readResponse(resp)
	if err != nil {
		return nil, err
	}

	return &authorizationInformation{
		header:  resp.Header,
		payload: data,
	}, nil
}

func (a *remoteAuthorizer) createRequest(ctx heimdall.Context, sub *subject.Subject) (*http.Request, error) {
	body, err := a.payload.Render(ctx, sub)
	if err != nil {
		return nil, err
	}

	req, err := a.e.CreateRequest(ctx.AppContext(), strings.NewReader(body))
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

func (a *remoteAuthorizer) calculateCacheKey(sub *subject.Subject) string {
	return ""
}
