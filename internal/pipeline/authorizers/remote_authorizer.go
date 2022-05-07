package authorizers

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	"github.com/dadrus/heimdall/internal/x"
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

func (ai *authorizationInformation) AddHeadersTo(headerNames []string, ctx heimdall.Context) {
	for _, headerName := range headerNames {
		headerValue := ai.header.Get(headerName)
		if len(headerValue) != 0 {
			ctx.AddResponseHeader(headerName, headerValue)
		}
	}
}

func (ai *authorizationInformation) AddAttributesTo(key string, sub *subject.Subject) {
	if len(ai.payload) != 0 {
		sub.Attributes[key] = ai.payload
	}
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
		cacheKey   string
		cacheEntry any
		authInfo   *authorizationInformation
		err        error
		ok         bool
	)

	if a.ttl != nil {
		cacheKey, err = a.calculateCacheKey(sub)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to calculate cache key. Will not be able to use cache.")
		} else {
			cacheEntry = cch.Get(cacheKey)
		}
	}

	if cacheEntry != nil {
		if authInfo, ok = cacheEntry.(*authorizationInformation); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing authorization information from cache")
		}
	}

	if authInfo == nil {
		authInfo, err = a.doAuthorize(ctx, sub)
		if err != nil {
			return err
		}

		if a.ttl != nil && len(cacheKey) != 0 {
			cch.Set(cacheKey, authInfo, *a.ttl)
		}
	}

	authInfo.AddHeadersTo(a.headersForUpstream, ctx)
	authInfo.AddAttributesTo(a.name, sub)

	return nil
}

func (a *remoteAuthorizer) doAuthorize(ctx heimdall.Context, sub *subject.Subject) (*authorizationInformation, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Calling remote authorization endpoint")

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
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
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
		NewWithMessagef(heimdall.ErrAuthorization,
			"authorization failed based on received response code: %v", resp.StatusCode)
}

func (a *remoteAuthorizer) WithConfig(rawConfig map[any]any) (Authorizer, error) {
	if len(rawConfig) == 0 {
		return a, nil
	}

	type _config struct {
		Headers                  map[string]template.Template `mapstructure:"headers"`
		Payload                  template.Template            `mapstructure:"payload"`
		ResponseHeadersToForward []string                     `mapstructure:"forward_response_headers_to_upstream"`
		CacheTTL                 *time.Duration               `mapstructure:"cache_ttl"`
	}

	var conf _config
	if err := mapstructure.Decode(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal remote authorizer config").
			CausedBy(err)
	}

	return &remoteAuthorizer{
		e:       a.e,
		payload: x.IfThenElse(len(conf.Payload) != 0, conf.Payload, a.payload),
		headers: x.IfThenElse(len(conf.Headers) != 0, conf.Headers, a.headers),
		headersForUpstream: x.IfThenElse(len(conf.ResponseHeadersToForward) != 0,
			conf.ResponseHeadersToForward, a.headersForUpstream),
		ttl: x.IfThenElse(conf.CacheTTL != nil, conf.CacheTTL, a.ttl),
	}, nil
}

func (a *remoteAuthorizer) calculateCacheKey(sub *subject.Subject) (string, error) {
	const int64BytesCount = 8

	rawSub, err := json.Marshal(sub)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to marshal subject data").
			CausedBy(err)
	}

	ttlBytes := make([]byte, int64BytesCount)
	if a.ttl != nil {
		binary.LittleEndian.PutUint64(ttlBytes, uint64(*a.ttl))
	}

	buf := bytes.NewBufferString("")
	for k, v := range a.headers {
		buf.Write([]byte(k))
		buf.Write([]byte(v))
	}

	hash := sha256.New()
	hash.Write([]byte(a.e.Hash()))
	hash.Write([]byte(a.name))
	hash.Write([]byte(strings.Join(a.headersForUpstream, ",")))
	hash.Write([]byte(a.payload))
	hash.Write(buf.Bytes())
	hash.Write(ttlBytes)
	hash.Write(rawSub)

	return hex.EncodeToString(hash.Sum(nil)), nil
}
