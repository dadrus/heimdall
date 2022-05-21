package authenticators

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(_ string, typ config.PipelineObjectType, conf map[string]any) (bool, Authenticator, error) {
			if typ != config.POTGeneric {
				return false, nil, nil
			}

			auth, err := newGenericAuthenticator(conf)

			return true, auth, err
		})
}

type genericAuthenticator struct {
	e   endpoint.Endpoint
	sf  SubjectFactory
	ads extractors.AuthDataExtractStrategy
	ttl time.Duration
}

func newGenericAuthenticator(rawConfig map[string]any) (*genericAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"`
		AuthDataSource extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source"`
		Session        Session                             `mapstructure:"session"`
		CacheTTL       *time.Duration                      `mapstructure:"cache_ttl"`
	}

	var conf _config

	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode generic authenticator config").
			CausedBy(err)
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate endpoint configuration").
			CausedBy(err)
	}

	if err := conf.Session.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate session configuration").
			CausedBy(err)
	}

	if conf.AuthDataSource == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no authentication_data_source configured")
	}

	return &genericAuthenticator{
		e:   conf.Endpoint,
		ads: conf.AuthDataSource,
		sf:  &conf.Session,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return 0 }),
	}, nil
}

func (a *genericAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using generic authenticator")

	authData, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrAuthentication,
			"failed to get authentication data from request").CausedBy(err)
	}

	payload, err := a.getSubjectInformation(ctx, authData)
	if err != nil {
		return nil, err
	}

	sub, err := a.sf.CreateSubject(payload)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from response").
			CausedBy(err)
	}

	return sub, nil
}

func (a *genericAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
	// this authenticator allows ttl to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		CacheTTL *time.Duration `mapstructure:"cache_ttl"`
	}

	var conf _config
	if err := decodeConfig(config, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to parse configuration").
			CausedBy(err)
	}

	return &genericAuthenticator{
		e:   a.e,
		sf:  a.sf,
		ads: a.ads,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return a.ttl }),
	}, nil
}

func (a *genericAuthenticator) getSubjectInformation(ctx heimdall.Context,
	authData extractors.AuthData,
) ([]byte, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	cch := cache.Ctx(ctx.AppContext())

	var (
		cacheKey       string
		cacheEntry     any
		cachedResponse []byte
		ok             bool
	)

	if a.ttl > 0 {
		cacheKey = a.calculateCacheKey(authData.Value())
		cacheEntry = cch.Get(cacheKey)
	}

	if cacheEntry != nil {
		if cachedResponse, ok = cacheEntry.([]byte); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing subject information from cache")

			return cachedResponse, nil
		}
	}

	payload, err := a.fetchSubjectInformation(ctx, authData)
	if err != nil {
		return nil, err
	}

	if a.ttl > 0 {
		cch.Set(cacheKey, payload, a.ttl)
	}

	return payload, nil
}

func (a *genericAuthenticator) fetchSubjectInformation(ctx heimdall.Context,
	authData extractors.AuthData,
) ([]byte, error) {
	req, err := a.e.CreateRequest(ctx.AppContext(), nil, nil)
	if err != nil {
		return nil, err
	}

	authData.ApplyTo(req)

	resp, err := a.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to the endpoint to get information about the user timed out").CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to the endpoint to get information about the user failed").CausedBy(err)
	}

	defer resp.Body.Close()

	return a.readResponse(resp)
}

func (*genericAuthenticator) readResponse(resp *http.Response) ([]byte, error) {
	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.
			NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode)
	}

	rawData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			CausedBy(err)
	}

	return rawData, nil
}

func (a *genericAuthenticator) calculateCacheKey(reference string) string {
	digest := sha256.New()
	digest.Write([]byte(a.e.Hash()))
	digest.Write([]byte(reference))

	return hex.EncodeToString(digest.Sum(nil))
}
