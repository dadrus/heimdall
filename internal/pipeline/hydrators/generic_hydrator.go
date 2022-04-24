package hydrators

import (
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

const (
	defaultTTL         = 10 * time.Second
	defaultCacheLeeway = 10 * time.Second
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerHydratorTypeFactory(
		func(id string, typ config.PipelineObjectType, conf map[any]any) (bool, Hydrator, error) {
			if typ != config.POTGeneric {
				return false, nil, nil
			}

			eh, err := newGenericHydrator(id, conf)

			return true, eh, err
		})
}

type genericHydrator struct {
	e          endpoint.Endpoint
	ttl        time.Duration
	payload    template.Template
	fwdHeaders []string
	fwdCookies []string
	name       string
}

func newGenericHydrator(id string, rawConfig map[any]any) (*genericHydrator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint `mapstructure:"endpoint"`
		ForwardHeaders []string          `mapstructure:"forward_headers"`
		ForwardCookies []string          `mapstructure:"forward_cookies"`
		Payload        template.Template `mapstructure:"payload"`
		CacheTTL       *time.Duration    `mapstructure:"cache_ttl"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT mutator config").
			CausedBy(err)
	}

	ttl := defaultTTL
	if conf.CacheTTL != nil {
		ttl = *conf.CacheTTL
	}

	return &genericHydrator{
		e:          conf.Endpoint,
		payload:    conf.Payload,
		fwdHeaders: conf.ForwardHeaders,
		fwdCookies: conf.ForwardCookies,
		ttl:        ttl,
		name:       id,
	}, nil
}

func (h *genericHydrator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Hydrating using generic hydrator")

	if sub == nil {
		return errorchain.NewWithMessage(heimdall.ErrArgument,
			"failed to execute generic hydrator due to 'nil' subject")
	}

	var hydrationResponse map[string]any

	cch := cache.Ctx(ctx.AppContext())

	cacheKey, err := h.calculateCacheKey(sub)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to calculate cache key. Will not be able to use cache.")
	} else if item := cch.Get(cacheKey); item != nil {
		if cachedResponse, ok := item.(map[string]any); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing hydration response from cache")

			hydrationResponse = cachedResponse
		}
	}

	if len(hydrationResponse) == 0 {
		respValue, err := h.callHydrationEndpoint(ctx, sub)
		if err != nil {
			return err
		}

		hydrationResponse = respValue

		if len(cacheKey) != 0 {
			cch.Set(cacheKey, hydrationResponse, h.ttl-defaultCacheLeeway)
		}
	}

	sub.Attributes[h.name] = hydrationResponse

	return nil
}

func (h *genericHydrator) callHydrationEndpoint(ctx heimdall.Context, sub *subject.Subject) (map[string]any, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Calling hydration endpoint")

	value, err := h.payload.Render(ctx, sub)
	if err != nil {
		return nil, err
	}

	req, err := h.e.CreateRequest(ctx.AppContext(), strings.NewReader(value))
	if err != nil {
		return nil, err
	}

	for _, headerName := range h.fwdHeaders {
		headerValue := ctx.RequestHeader(headerName)
		if len(headerValue) == 0 {
			logger.Warn().Str("header", headerName).
				Msg("Header not present in the request but configured to be forwarded")
		}

		req.Header.Add(headerName, headerValue)
	}

	for _, cookieName := range h.fwdCookies {
		cookieValue := ctx.RequestCookie(cookieName)
		if len(cookieValue) == 0 {
			logger.Warn().Str("cookie", cookieName).
				Msg("Cookie not present in the request but configured to be forwarded")
		}

		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	resp, err := h.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to the introspection endpoint timed out").CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to the introspection endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	return h.readResponse(resp)
}

func (h *genericHydrator) readResponse(resp *http.Response) (map[string]any, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
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

func (h *genericHydrator) calculateCacheKey(sub *subject.Subject) (string, error) {
	const int64BytesCount = 8

	rawSub, err := json.Marshal(sub)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to marshal subject data").
			CausedBy(err)
	}

	ttlBytes := make([]byte, int64BytesCount)
	binary.LittleEndian.PutUint64(ttlBytes, uint64(h.ttl))

	hash := sha256.New()
	hash.Write([]byte(h.name))
	hash.Write([]byte(strings.Join(h.fwdHeaders, ",")))
	hash.Write([]byte(strings.Join(h.fwdCookies, ",")))
	hash.Write([]byte(h.payload))
	hash.Write([]byte(h.e.URL))
	hash.Write(ttlBytes)
	hash.Write(rawSub)

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (h *genericHydrator) WithConfig(rawConfig map[any]any) (Hydrator, error) {
	if len(rawConfig) == 0 {
		return h, nil
	}

	type _config struct {
		ForwardHeaders []string           `mapstructure:"forward_headers"`
		ForwardCookies []string           `mapstructure:"forward_cookies"`
		Payload        *template.Template `mapstructure:"payload"`
		CacheTTL       *time.Duration     `mapstructure:"cache_ttl"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT mutator config").
			CausedBy(err)
	}

	return &genericHydrator{
		e:    h.e,
		name: h.name,
		payload: x.IfThenElseExec(conf.Payload != nil,
			func() template.Template { return *conf.Payload },
			func() template.Template { return h.payload }),
		fwdHeaders: x.IfThenElse(len(conf.ForwardHeaders) != 0, conf.ForwardHeaders, h.fwdHeaders),
		fwdCookies: x.IfThenElse(len(conf.ForwardCookies) != 0, conf.ForwardCookies, h.fwdCookies),
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return h.ttl }),
	}, nil
}
