package authenticators

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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

const defaultGenericAuthenticatorTTL = 10 * time.Minute

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
	e                    endpoint.Endpoint
	sf                   SubjectFactory
	ads                  extractors.AuthDataExtractStrategy
	ttl                  *time.Duration
	sessionConf          *SessionConfig
	allowFallbackOnError bool
}

func newGenericAuthenticator(rawConfig map[string]any) (*genericAuthenticator, error) {
	type Config struct {
		Endpoint             endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"`
		AuthDataSource       extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source"`
		SubjectInfo          SubjectInfo                         `mapstructure:"subject"`
		SessionInfo          *SessionConfig                      `mapstructure:"session"`
		CacheTTL             *time.Duration                      `mapstructure:"cache_ttl"`
		AllowFallbackOnError bool                                `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config

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

	if err := conf.SubjectInfo.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate subject configuration").
			CausedBy(err)
	}

	if conf.AuthDataSource == nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "no authentication_data_source configured")
	}

	return &genericAuthenticator{
		e:                    conf.Endpoint,
		ads:                  conf.AuthDataSource,
		sf:                   &conf.SubjectInfo,
		ttl:                  conf.CacheTTL,
		allowFallbackOnError: conf.AllowFallbackOnError,
		sessionConf:          conf.SessionInfo,
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

	type Config struct {
		CacheTTL             *time.Duration `mapstructure:"cache_ttl"`
		AllowFallbackOnError *bool          `mapstructure:"allow_fallback_on_error"`
	}

	var conf Config
	if err := decodeConfig(config, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to parse configuration").
			CausedBy(err)
	}

	return &genericAuthenticator{
		e:   a.e,
		sf:  a.sf,
		ads: a.ads,
		ttl: x.IfThenElse(conf.CacheTTL != nil, conf.CacheTTL, a.ttl),
		allowFallbackOnError: x.IfThenElseExec(conf.AllowFallbackOnError != nil,
			func() bool { return *conf.AllowFallbackOnError },
			func() bool { return a.allowFallbackOnError }),
	}, nil
}

func (a *genericAuthenticator) IsFallbackOnErrorAllowed() bool {
	return a.allowFallbackOnError
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
		session        *Session
	)

	if a.isCacheEnabled() {
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

	if a.sessionConf != nil {
		session, err = a.sessionConf.CreateSession(payload)
		if err != nil {
			return nil, errorchain.New(heimdall.ErrInternal).CausedBy(err)
		}

		if session != nil {
			if err = session.Assert(); err != nil {
				return nil, errorchain.New(heimdall.ErrAuthentication).CausedBy(err)
			}
		}
	}

	if cacheTTL := a.getCacheTTL(session); cacheTTL > 0 {
		cch.Set(cacheKey, payload, cacheTTL)
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

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			CausedBy(err)
	}

	return rawData, nil
}

func (a *genericAuthenticator) isCacheEnabled() bool {
	// cache is enabled if ttl is configured and is > 0
	return a.ttl != nil && *a.ttl > 0
}

func (a *genericAuthenticator) getCacheTTL(sessionValidity *Session) time.Duration {
	// timeLeeway defines the default time deviation to ensure the session is still valid
	// when used from cache
	const timeLeeway = 10

	if !a.isCacheEnabled() {
		return 0
	}

	// we cache using the settings in the configured ttl.
	// It is however ensured, that this ttl does not exceed the ttl of the session itself
	// (if this information is available)
	sessionTTL := x.IfThenElseExec(sessionValidity != nil && sessionValidity.naf != time.Time{},
		func() time.Duration {
			expiresIn := sessionValidity.naf.Unix() - time.Now().Unix() - timeLeeway

			return x.IfThenElse(expiresIn > 0, time.Duration(expiresIn)*time.Second, 0)
		},
		func() time.Duration { return 0 })

	if sessionTTL <= 0 {
		return *a.ttl
	}

	return x.IfThenElse(*a.ttl < sessionTTL, *a.ttl, sessionTTL)
}

func (a *genericAuthenticator) calculateCacheKey(reference string) string {
	digest := sha256.New()
	digest.Write([]byte(a.e.Hash()))
	digest.Write([]byte(reference))

	return hex.EncodeToString(digest.Sum(nil))
}
