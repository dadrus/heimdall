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
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Authenticator, error) {
			if typ != config.POTAuthenticationData {
				return false, nil, nil
			}

			auth, err := newAuthenticationDataAuthenticator(conf)

			return true, auth, err
		})
}

type authenticationDataAuthenticator struct {
	e   endpoint.Endpoint
	se  SubjectFactory
	adg extractors.AuthDataExtractStrategy
	ttl *time.Duration
}

func newAuthenticationDataAuthenticator(rawConfig map[string]any) (*authenticationDataAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"`
		AuthDataSource extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source"`
		Session        Session                             `mapstructure:"session"`
		CacheTTL       *time.Duration                      `mapstructure:"cache_ttl"`
	}

	var conf _config

	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode authentication data authenticator config").
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

	return &authenticationDataAuthenticator{
		e:   conf.Endpoint,
		adg: conf.AuthDataSource,
		se:  &conf.Session,
		ttl: conf.CacheTTL,
	}, nil
}

func (a *authenticationDataAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using authentication data authenticator")

	authData, err := a.adg.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.New(heimdall.ErrAuthentication).CausedBy(err)
	}

	payload, err := a.getSubjectInformation(ctx, authData)
	if err != nil {
		return nil, err
	}

	sub, err := a.se.CreateSubject(payload)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from response").
			CausedBy(err)
	}

	return sub, nil
}

func (a *authenticationDataAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
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

	return &authenticationDataAuthenticator{
		e:   a.e,
		se:  a.se,
		adg: a.adg,
		ttl: x.IfThenElse(conf.CacheTTL != nil, conf.CacheTTL, a.ttl),
	}, nil
}

func (a *authenticationDataAuthenticator) getSubjectInformation(
	ctx heimdall.Context,
	authData extractors.AuthData,
) ([]byte, error) {
	cch := cache.Ctx(ctx.AppContext())
	logger := zerolog.Ctx(ctx.AppContext())
	cacheKey := a.calculateCacheKey(authData.Value())

	var cacheTTL time.Duration
	if a.ttl != nil {
		cacheTTL = *a.ttl
	}

	if cacheTTL != 0 {
		if item := cch.Get(cacheKey); item != nil {
			if cachedSubjectInfo, ok := item.([]byte); !ok {
				logger.Warn().Msg("Wrong object type from cache")
				cch.Delete(cacheKey)
			} else {
				logger.Debug().Msg("Reusing subject information from cache")

				return cachedSubjectInfo, nil
			}
		}
	}

	payload, err := a.fetchSubjectInformation(ctx, authData)
	if err != nil {
		return nil, err
	}

	if cacheTTL != 0 {
		cch.Set(cacheKey, payload, cacheTTL)
	}

	return payload, nil
}

func (a *authenticationDataAuthenticator) fetchSubjectInformation(
	ctx heimdall.Context,
	authData extractors.AuthData,
) ([]byte, error) {
	req, err := a.e.CreateRequest(ctx.AppContext(), nil)
	if err != nil {
		return nil, err
	}

	authData.ApplyTo(req)

	resp, err := a.e.CreateClient().Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to get information about the user timed out").CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to get information about the user failed").CausedBy(err)
	}

	defer resp.Body.Close()

	return a.readResponse(resp)
}

func (*authenticationDataAuthenticator) readResponse(resp *http.Response) ([]byte, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to read response").
				CausedBy(err)
		}

		return rawData, nil
	}

	return nil, errorchain.
		NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode)
}

func (a *authenticationDataAuthenticator) calculateCacheKey(reference string) string {
	digest := sha256.New()
	digest.Write([]byte(a.e.URL))
	digest.Write([]byte(reference))

	return hex.EncodeToString(digest.Sum(nil))
}
