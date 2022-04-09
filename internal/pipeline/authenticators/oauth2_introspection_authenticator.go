package authenticators

import (
	"crypto/sha256"
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
	"github.com/dadrus/heimdall/internal/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	registerAuthenticatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, Authenticator, error) {
			if typ != config.POTOAuth2Introspection {
				return false, nil, nil
			}

			auth, err := newOAuth2IntrospectionAuthenticator(conf)

			return true, auth, err
		})
}

type oauth2IntrospectionAuthenticator struct {
	e   endpoint.Endpoint
	a   oauth2.Expectation
	sf  SubjectFactory
	adg extractors.AuthDataExtractStrategy
	ttl *time.Duration
}

func newOAuth2IntrospectionAuthenticator(rawConfig map[string]any) (*oauth2IntrospectionAuthenticator, error) {
	type _config struct {
		Endpoint   endpoint.Endpoint  `mapstructure:"introspection_endpoint"`
		Assertions oauth2.Expectation `mapstructure:"introspection_response_assertions"`
		Session    Session            `mapstructure:"session"`
		CacheTTL   *time.Duration     `mapstructure:"cache_ttl"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal oauth2 introspection authenticator config").
			CausedBy(err)
	}

	if err := conf.Endpoint.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate endpoint configuration").
			CausedBy(err)
	}

	if err := conf.Assertions.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate assertions configuration").
			CausedBy(err)
	}

	if err := conf.Session.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate session configuration").
			CausedBy(err)
	}

	if conf.Endpoint.Headers == nil {
		conf.Endpoint.Headers = make(map[string]string)
	}

	if _, ok := conf.Endpoint.Headers["Content-Type"]; !ok {
		conf.Endpoint.Headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	if _, ok := conf.Endpoint.Headers["Accept-Type"]; !ok {
		conf.Endpoint.Headers["Accept-Type"] = "application/json"
	}

	if len(conf.Endpoint.Method) == 0 {
		conf.Endpoint.Method = http.MethodPost
	}

	if len(conf.Assertions.AllowedAlgorithms) == 0 {
		conf.Assertions.AllowedAlgorithms = defaultAllowedAlgorithms()
	}

	extractor := extractors.CompositeExtractStrategy{
		extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"},
		extractors.CookieValueExtractStrategy{Name: "access_token"},
		extractors.QueryParameterExtractStrategy{Name: "access_token"},
	}

	return &oauth2IntrospectionAuthenticator{
		adg: extractor,
		e:   conf.Endpoint,
		a:   conf.Assertions,
		sf:  &conf.Session,
		ttl: conf.CacheTTL,
	}, nil
}

func (a *oauth2IntrospectionAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Authenticating using OAuth2 introspect authenticator")

	accessToken, err := a.adg.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no access token present").
			CausedBy(err)
	}

	rawResp, err := a.getSubjectInformation(ctx, accessToken.Value())
	if err != nil {
		return nil, err
	}

	sub, err := a.sf.CreateSubject(rawResp)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from introspection response").
			CausedBy(err)
	}

	return sub, nil
}

func (a *oauth2IntrospectionAuthenticator) WithConfig(config map[string]any) (Authenticator, error) {
	// this authenticator allows assertions and ttl to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		Assertions *oauth2.Expectation `mapstructure:"introspection_response_assertions"`
		CacheTTL   *time.Duration      `mapstructure:"cache_ttl"`
	}

	var conf _config
	if err := decodeConfig(config, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to parse configuration").
			CausedBy(err)
	}

	var assertions oauth2.Expectation
	if conf.Assertions != nil {
		assertions = *conf.Assertions
	} else {
		assertions = a.a
	}

	return &oauth2IntrospectionAuthenticator{
		e:   a.e,
		a:   assertions,
		sf:  a.sf,
		adg: a.adg,
		ttl: x.IfThenElse(conf.CacheTTL != nil, conf.CacheTTL, a.ttl),
	}, nil
}

func (a *oauth2IntrospectionAuthenticator) getSubjectInformation(
	ctx heimdall.Context,
	token string,
) ([]byte, error) {
	cch := cache.Ctx(ctx.AppContext())
	logger := zerolog.Ctx(ctx.AppContext())
	cacheKey := a.calculateCacheKey(token)

	if item := cch.Get(cacheKey); item != nil {
		if cachedResponse, ok := item.([]byte); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing introspection response from cache")

			return cachedResponse, nil
		}
	}

	introspectResp, rawResp, err := a.fetchTokenIntrospectionResponse(ctx, token)
	if err != nil {
		return nil, err
	}

	if err = introspectResp.Validate(a.a); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "access token does not satisfy assertion conditions").
			CausedBy(err)
	}

	if cacheTTL := a.getCacheTTL(introspectResp); cacheTTL != 0 {
		cch.Set(cacheKey, rawResp, cacheTTL)
	}

	return rawResp, nil
}

func (a *oauth2IntrospectionAuthenticator) fetchTokenIntrospectionResponse(
	ctx heimdall.Context,
	token string,
) (*oauth2.IntrospectionResponse, []byte, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Msg("Retrieving information about the access token from the introspection endpoint")

	req, err := a.e.CreateRequest(ctx.AppContext(), strings.NewReader(
		url.Values{
			"token":           []string{token},
			"token_type_hint": []string{"access_token"},
		}.Encode()))
	if err != nil {
		return nil, nil, err
	}

	resp, err := a.e.CreateClient().Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to the introspection endpoint timed out").CausedBy(err)
		}

		return nil, nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to the introspection endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	return a.readIntrospectionResponse(resp)
}

func (a *oauth2IntrospectionAuthenticator) readIntrospectionResponse(
	resp *http.Response,
) (*oauth2.IntrospectionResponse, []byte, error) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rawData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to read response").
				CausedBy(err)
		}

		var resp oauth2.IntrospectionResponse
		if err = json.Unmarshal(rawData, &resp); err != nil {
			return nil, nil, errorchain.
				NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received introspection response").
				CausedBy(err)
		}

		return &resp, rawData, nil
	}

	return nil, nil, errorchain.
		NewWithMessagef(heimdall.ErrCommunication, "unexpected response code: %v", resp.StatusCode)
}

func (a *oauth2IntrospectionAuthenticator) getCacheTTL(introspectResp *oauth2.IntrospectionResponse) time.Duration {
	var cacheTTL time.Duration

	// we cache be default using the settings in the introspection response (if available)
	// or if ttl has been configured (which overwrites the settings in the response). Latter
	// overwrites the settings in the introspection response
	if a.ttl == nil || (a.ttl != nil && *a.ttl != 0) {
		// timeLeeway defines the default time deviation to ensure the token is still valid
		// when used from cache
		const timeLeeway = 10

		if a.ttl != nil && *a.ttl != 0 {
			cacheTTL = *a.ttl
		} else if introspectResp.Expiry != nil {
			expiresIn := introspectResp.Expiry.Time().Unix() - time.Now().Unix() - timeLeeway
			if expiresIn > 0 {
				cacheTTL = time.Duration(expiresIn) * time.Second
			}
		}
	}

	return cacheTTL
}

func (a *oauth2IntrospectionAuthenticator) calculateCacheKey(reference string) string {
	digest := sha256.New()
	digest.Write([]byte(a.e.URL))
	digest.Write([]byte(reference))

	return hex.EncodeToString(digest.Sum(nil))
}
