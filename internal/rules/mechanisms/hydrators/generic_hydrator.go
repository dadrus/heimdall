package hydrators

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contenttype"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	defaultTTL = 10 * time.Second
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerHydratorTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Hydrator, error) {
			if typ != HydratorGeneric {
				return false, nil, nil
			}

			eh, err := newGenericHydrator(id, conf)

			return true, eh, err
		})
}

type hydrationData struct {
	payload any
}

type genericHydrator struct {
	id         string
	e          endpoint.Endpoint
	ttl        time.Duration
	payload    template.Template
	fwdHeaders []string
	fwdCookies []string
}

func newGenericHydrator(id string, rawConfig map[string]any) (*genericHydrator, error) {
	type Config struct {
		Endpoint       endpoint.Endpoint `mapstructure:"endpoint"`
		ForwardHeaders []string          `mapstructure:"forward_headers"`
		ForwardCookies []string          `mapstructure:"forward_cookies"`
		Payload        template.Template `mapstructure:"payload"`
		CacheTTL       *time.Duration    `mapstructure:"cache_ttl"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal generic hydrator config").
			CausedBy(err)
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate endpoint configuration").
			CausedBy(err)
	}

	ttl := defaultTTL
	if conf.CacheTTL != nil {
		ttl = *conf.CacheTTL
	}

	return &genericHydrator{
		id:         id,
		e:          conf.Endpoint,
		payload:    conf.Payload,
		fwdHeaders: conf.ForwardHeaders,
		fwdCookies: conf.ForwardCookies,
		ttl:        ttl,
	}, nil
}

func (h *genericHydrator) Execute(ctx heimdall.Context, sub *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Hydrating using generic hydrator")

	if sub == nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to execute generic hydrator due to 'nil' subject").
			WithErrorContext(h)
	}

	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheKey          string
		err               error
		ok                bool
		cacheEntry        any
		hydrationResponse *hydrationData
	)

	if h.ttl > 0 {
		cacheKey, err = h.calculateCacheKey(sub)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to calculate cache key. Will not be able to use cache.")
		} else {
			cacheEntry = cch.Get(cacheKey)
		}
	}

	if cacheEntry != nil {
		if hydrationResponse, ok = cacheEntry.(*hydrationData); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing hydration response from cache")
		}
	}

	if hydrationResponse == nil {
		hydrationResponse, err = h.callHydrationEndpoint(ctx, sub)
		if err != nil {
			return err
		}

		if h.ttl > 0 && len(cacheKey) != 0 {
			cch.Set(cacheKey, hydrationResponse, h.ttl)
		}
	}

	if hydrationResponse.payload != nil {
		sub.Attributes[h.id] = hydrationResponse.payload
	}

	return nil
}

func (h *genericHydrator) WithConfig(rawConfig map[string]any) (Hydrator, error) {
	if len(rawConfig) == 0 {
		return h, nil
	}

	type Config struct {
		ForwardHeaders []string          `mapstructure:"forward_headers"`
		ForwardCookies []string          `mapstructure:"forward_cookies"`
		Payload        template.Template `mapstructure:"payload"`
		CacheTTL       *time.Duration    `mapstructure:"cache_ttl"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal JWT mutator config").
			CausedBy(err)
	}

	return &genericHydrator{
		id:         h.id,
		e:          h.e,
		payload:    x.IfThenElse(conf.Payload != nil, conf.Payload, h.payload),
		fwdHeaders: x.IfThenElse(len(conf.ForwardHeaders) != 0, conf.ForwardHeaders, h.fwdHeaders),
		fwdCookies: x.IfThenElse(len(conf.ForwardCookies) != 0, conf.ForwardCookies, h.fwdCookies),
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return h.ttl }),
	}, nil
}

func (h *genericHydrator) HandlerID() string {
	return h.id
}

func (h *genericHydrator) callHydrationEndpoint(ctx heimdall.Context, sub *subject.Subject) (*hydrationData, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Calling hydration endpoint")

	req, err := h.createRequest(ctx, sub)
	if err != nil {
		return nil, err
	}

	resp, err := h.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout, "request to the hydration endpoint timed out").
				WithErrorContext(h).
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication, "request to the hydration endpoint failed").
			WithErrorContext(h).
			CausedBy(err)
	}

	defer resp.Body.Close()

	data, err := h.readResponse(ctx, resp)
	if err != nil {
		return nil, err
	}

	return &hydrationData{payload: data}, nil
}

func (h *genericHydrator) createRequest(ctx heimdall.Context, sub *subject.Subject) (*http.Request, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	var body io.Reader

	if h.payload != nil {
		value, err := h.payload.Render(ctx, sub)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to render payload for the hydration endpoint").
				WithErrorContext(h).
				CausedBy(err)
		}

		body = strings.NewReader(value)
	}

	req, err := h.e.CreateRequest(ctx.AppContext(), body,
		endpoint.RenderFunc(func(value string) (string, error) {
			tpl, err := template.New(value)
			if err != nil {
				return "", errorchain.
					NewWithMessage(heimdall.ErrInternal, "failed to create template").
					WithErrorContext(h).
					CausedBy(err)
			}

			return tpl.Render(nil, sub)
		}))
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			WithErrorContext(h).
			CausedBy(err)
	}

	for _, headerName := range h.fwdHeaders {
		headerValue := ctx.RequestHeader(headerName)
		if len(headerValue) == 0 {
			logger.Warn().Str("_header", headerName).
				Msg("Header not present in the request but configured to be forwarded")
		}

		req.Header.Add(headerName, headerValue)
	}

	for _, cookieName := range h.fwdCookies {
		cookieValue := ctx.RequestCookie(cookieName)
		if len(cookieValue) == 0 {
			logger.Warn().Str("_cookie", cookieName).
				Msg("Cookie not present in the request but configured to be forwarded")
		}

		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	return req, nil
}

func (h *genericHydrator) readResponse(ctx heimdall.Context, resp *http.Response) (any, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode).
			WithErrorContext(h)
	}

	if resp.ContentLength == 0 {
		logger.Warn().Msg("No data received from the hydration endpoint")

		return nil, nil
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(h).
			CausedBy(err)
	}

	contentType := resp.Header.Get("Content-Type")

	logger.Debug().Str("_content_type", contentType).Msg("Response received")

	decoder, err := contenttype.NewDecoder(contentType)
	if err != nil {
		logger.Warn().Str("_content_type", contentType).
			Msg("Content type is not supported. Treating it as string")

		return string(rawData), nil // nolint: nilerr
	}

	result, err := decoder.Decode(rawData)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal response").
			WithErrorContext(h).
			CausedBy(err)
	}

	return result, nil
}

func (h *genericHydrator) calculateCacheKey(sub *subject.Subject) (string, error) {
	const int64BytesCount = 8

	rawSub, err := json.Marshal(sub)
	if err != nil {
		return "", errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to marshal subject data").
			WithErrorContext(h).
			CausedBy(err)
	}

	ttlBytes := make([]byte, int64BytesCount)
	binary.LittleEndian.PutUint64(ttlBytes, uint64(h.ttl))

	hash := sha256.New()
	hash.Write([]byte(h.id))
	hash.Write([]byte(strings.Join(h.fwdHeaders, ",")))
	hash.Write([]byte(strings.Join(h.fwdCookies, ",")))
	hash.Write(x.IfThenElseExec(h.payload != nil,
		func() []byte { return []byte(h.payload.Hash()) },
		func() []byte { return []byte("nil") }))
	hash.Write([]byte(h.e.Hash()))
	hash.Write(ttlBytes)
	hash.Write(rawSub)

	return hex.EncodeToString(hash.Sum(nil)), nil
}
