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
	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorGeneric {
				return false, nil, nil
			}

			auth, err := newGenericAuthenticator(id, conf)

			return true, auth, err
		})
}

type genericAuthenticator struct {
	id                   string
	e                    endpoint.Endpoint
	sf                   SubjectFactory
	ads                  extractors.AuthDataExtractStrategy
	ttl                  time.Duration
	sessionLifespanConf  *SessionLifespanConfig
	allowFallbackOnError bool
}

func newGenericAuthenticator(id string, rawConfig map[string]any) (*genericAuthenticator, error) {
	type Config struct {
		Endpoint              endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"`
		AuthDataSource        extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source"`
		SubjectInfo           SubjectInfo                         `mapstructure:"subject"`
		SessionLifespanConfig *SessionLifespanConfig              `mapstructure:"session_lifespan"`
		CacheTTL              *time.Duration                      `mapstructure:"cache_ttl"`
		AllowFallbackOnError  bool                                `mapstructure:"allow_fallback_on_error"`
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
		id:  id,
		e:   conf.Endpoint,
		ads: conf.AuthDataSource,
		sf:  &conf.SubjectInfo,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return 0 }),
		allowFallbackOnError: conf.AllowFallbackOnError,
		sessionLifespanConf:  conf.SessionLifespanConfig,
	}, nil
}

func (a *genericAuthenticator) Execute(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using generic authenticator")

	authData, err := a.ads.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "failed to get authentication data from request").
			WithErrorContext(a).
			CausedBy(err)
	}

	payload, err := a.getSubjectInformation(ctx, authData)
	if err != nil {
		return nil, err
	}

	sub, err := a.sf.CreateSubject(payload)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from response").
			WithErrorContext(a).
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
		id:  a.id,
		e:   a.e,
		sf:  a.sf,
		ads: a.ads,
		ttl: x.IfThenElseExec(conf.CacheTTL != nil,
			func() time.Duration { return *conf.CacheTTL },
			func() time.Duration { return a.ttl }),
		allowFallbackOnError: x.IfThenElseExec(conf.AllowFallbackOnError != nil,
			func() bool { return *conf.AllowFallbackOnError },
			func() bool { return a.allowFallbackOnError }),
		sessionLifespanConf: a.sessionLifespanConf,
	}, nil
}

func (a *genericAuthenticator) IsFallbackOnErrorAllowed() bool {
	return a.allowFallbackOnError
}

func (a *genericAuthenticator) HandlerID() string {
	return a.id
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
		session        *SessionLifespan
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

	if a.sessionLifespanConf != nil {
		session, err = a.sessionLifespanConf.CreateSessionLifespan(payload)
		if err != nil {
			return nil, errorchain.New(heimdall.ErrInternal).WithErrorContext(a).CausedBy(err)
		}

		if session != nil {
			if err = session.Assert(); err != nil {
				return nil, errorchain.New(heimdall.ErrAuthentication).WithErrorContext(a).CausedBy(err)
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
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed creating request").
			WithErrorContext(a).
			CausedBy(err)
	}

	authData.ApplyTo(req)

	resp, err := a.e.CreateClient(req.URL.Hostname()).Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrCommunicationTimeout,
					"request to the endpoint to get information about the user timed out").
				WithErrorContext(a).
				CausedBy(err)
		}

		return nil, errorchain.
			NewWithMessage(heimdall.ErrCommunication,
				"request to the endpoint to get information about the user failed").
			WithErrorContext(a).
			CausedBy(err)
	}

	defer resp.Body.Close()

	return a.readResponse(resp)
}

func (a *genericAuthenticator) readResponse(resp *http.Response) ([]byte, error) {
	if !(resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices) {
		return nil, errorchain.NewWithMessagef(heimdall.ErrCommunication,
			"unexpected response code: %v", resp.StatusCode).WithErrorContext(a)
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to read response").
			WithErrorContext(a).
			CausedBy(err)
	}

	return rawData, nil
}

func (a *genericAuthenticator) getCacheTTL(sessionLifespan *SessionLifespan) time.Duration {
	// timeLeeway defines the default time deviation to ensure the session is still valid
	// when used from cache
	const timeLeeway = 10

	if a.ttl <= 0 {
		return 0
	}

	// we cache using the settings in the configured ttl.
	// It is however ensured, that this ttl does not exceed the ttl of the session itself
	// (if this information is available)
	if sessionLifespan != nil && !sessionLifespan.exp.Equal(time.Time{}) {
		expiresIn := sessionLifespan.exp.Unix() - time.Now().Unix() - timeLeeway
		expirationTTL := x.IfThenElse(expiresIn > 0, time.Duration(expiresIn)*time.Second, 0)

		return x.IfThenElse(a.ttl < expirationTTL, a.ttl, expirationTTL)
	}

	return a.ttl
}

func (a *genericAuthenticator) calculateCacheKey(reference string) string {
	digest := sha256.New()
	digest.Write([]byte(a.e.Hash()))
	digest.Write([]byte(reference))

	return hex.EncodeToString(digest.Sum(nil))
}
