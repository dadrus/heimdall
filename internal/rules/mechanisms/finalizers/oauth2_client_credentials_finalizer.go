package finalizers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

// by intention. Used only during application bootstrap
//
//nolint:gochecknoinits
func init() {
	registerTypeFactory(
		func(id string, typ string, conf map[string]any) (bool, Finalizer, error) {
			if typ != FinalizerOAuth2ClientCredentials {
				return false, nil, nil
			}

			finalizer, err := newOAuth2ClientCredentialsFinalizer(id, conf)

			return true, finalizer, err
		})
}

type tokenEndpointResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   *int64 `json:"expires_in,omitempty"`
}

type oauth2ClientCredentialsFinalizer struct {
	id           string
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
	ttl          *time.Duration
	headerName   string
	headerScheme string
}

func newOAuth2ClientCredentialsFinalizer(
	id string,
	rawConfig map[string]any,
) (*oauth2ClientCredentialsFinalizer, error) {
	type HeaderConfig struct {
		Name   string `mapstructure:"name"   validate:"required"`
		Scheme string `mapstructure:"scheme"`
	}

	type Config struct {
		TokenURL     string         `mapstructure:"token_url"     validate:"required,http_url"`
		ClientID     string         `mapstructure:"client_id"     validate:"required"`
		ClientSecret string         `mapstructure:"client_secret" validate:"required"`
		Scopes       []string       `mapstructure:"scopes"`
		TTL          *time.Duration `mapstructure:"cache_ttl"`
		Header       *HeaderConfig  `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to unmarshal oauth2_client_credentials finalizer config").CausedBy(err)
	}

	if err := validation.ValidateStruct(conf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed validating oauth2_client_credentials finalizer config").CausedBy(err)
	}

	return &oauth2ClientCredentialsFinalizer{
		id:           id,
		tokenURL:     conf.TokenURL,
		clientID:     conf.ClientID,
		clientSecret: conf.ClientSecret,
		scopes:       conf.Scopes,
		ttl:          conf.TTL,
		headerName: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Name },
			func() string { return "Authorization" }),
		headerScheme: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Scheme },
			func() string { return "Bearer" }),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) ContinueOnError() bool { return false }
func (f *oauth2ClientCredentialsFinalizer) ID() string            { return f.id }

func (f *oauth2ClientCredentialsFinalizer) WithConfig(rawConfig map[string]any) (Finalizer, error) {
	type HeaderConfig struct {
		Name   string `mapstructure:"name"   validate:"required"`
		Scheme string `mapstructure:"scheme"`
	}

	type Config struct {
		Scopes []string       `mapstructure:"scopes"`
		TTL    *time.Duration `mapstructure:"cache_ttl"`
		Header *HeaderConfig  `mapstructure:"header"`
	}

	var conf Config
	if err := decodeConfig(rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to unmarshal oauth2_client_credentials finalizer config").CausedBy(err)
	}

	if err := validation.ValidateStruct(conf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed validating oauth2_client_credentials finalizer config").CausedBy(err)
	}

	return &oauth2ClientCredentialsFinalizer{
		id:           f.id,
		tokenURL:     f.tokenURL,
		clientID:     f.clientID,
		clientSecret: f.clientSecret,
		scopes:       x.IfThenElse(conf.Scopes != nil, conf.Scopes, f.scopes),
		ttl:          x.IfThenElse(conf.TTL != nil, conf.TTL, f.ttl),
		headerName: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Name },
			func() string { return f.headerName }),
		headerScheme: x.IfThenElseExec(conf.Header != nil,
			func() string { return conf.Header.Scheme },
			func() string { return f.headerScheme }),
	}, nil
}

func (f *oauth2ClientCredentialsFinalizer) Execute(ctx heimdall.Context, _ *subject.Subject) error {
	logger := zerolog.Ctx(ctx.AppContext())
	logger.Debug().Msg("Finalizing using oauth2_client_credentials finalizer")

	cch := cache.Ctx(ctx.AppContext())

	var (
		ok         bool
		err        error
		cacheKey   string
		cacheEntry any
		tokenInfo  *tokenEndpointResponse
	)

	if f.isCacheEnabled() {
		cacheKey = f.calculateCacheKey()
		cacheEntry = cch.Get(cacheKey)
	}

	if cacheEntry != nil {
		if tokenInfo, ok = cacheEntry.(*tokenEndpointResponse); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing access token from cache")
		}
	}

	if tokenInfo == nil {
		logger.Debug().Msg("Retrieving new access token")

		tokenInfo, err = f.getAccessToken(ctx.AppContext())
		if err != nil {
			return err
		}

		if cacheTTL := f.getCacheTTL(tokenInfo); cacheTTL > 0 {
			cch.Set(cacheKey, tokenInfo, cacheTTL)
		}
	}

	ctx.AddHeaderForUpstream(f.headerName, fmt.Sprintf("%s %s", f.headerScheme, tokenInfo.AccessToken))

	return nil
}

func (f *oauth2ClientCredentialsFinalizer) calculateCacheKey() string {
	const int64BytesCount = 8

	ttlBytes := make([]byte, int64BytesCount)
	if f.ttl != nil {
		binary.LittleEndian.PutUint64(ttlBytes, uint64(*f.ttl))
	} else {
		binary.LittleEndian.PutUint64(ttlBytes, 0)
	}

	digest := sha256.New()
	digest.Write(stringx.ToBytes(FinalizerOAuth2ClientCredentials))
	digest.Write(stringx.ToBytes(f.clientID))
	digest.Write(stringx.ToBytes(f.clientSecret))
	digest.Write(stringx.ToBytes(f.tokenURL))
	digest.Write(stringx.ToBytes(strings.Join(f.scopes, "")))
	digest.Write(ttlBytes)

	return hex.EncodeToString(digest.Sum(nil))
}

func (f *oauth2ClientCredentialsFinalizer) getAccessToken(ctx context.Context) (*tokenEndpointResponse, error) {
	ept := endpoint.Endpoint{
		URL:    f.tokenURL,
		Method: http.MethodPost,
		AuthStrategy: &endpoint.BasicAuthStrategy{
			User:     url.QueryEscape(f.clientID),
			Password: url.QueryEscape(f.clientSecret),
		},
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept-Type":  "application/json",
		},
	}

	data := url.Values{"grant_type": []string{"client_credentials"}}
	if len(f.scopes) != 0 {
		data.Add("scope", strings.Join(f.scopes, " "))
	}

	rawData, err := ept.SendRequest(ctx, strings.NewReader(data.Encode()), nil)
	if err != nil {
		return nil, err
	}

	var resp tokenEndpointResponse
	if err := json.Unmarshal(rawData, &resp); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal response").
			CausedBy(err)
	}

	return &resp, nil
}

func (f *oauth2ClientCredentialsFinalizer) getCacheTTL(resp *tokenEndpointResponse) time.Duration {
	// timeLeeway defines the default time deviation to ensure the token is still valid
	// when used from cache
	const timeLeeway = 5

	if !f.isCacheEnabled() {
		return 0
	}

	// we cache by default using the settings in the token endpoint response (if available)
	// or if ttl has been configured. Latter overwrites the settings in the token endpoint response
	// if it is shorter than the ttl in the token endpoint response
	tokenEndpointResponseTTL := x.IfThenElseExec(resp.ExpiresIn != nil,
		func() time.Duration {
			expiresIn := *resp.ExpiresIn - timeLeeway

			return x.IfThenElse(expiresIn > 0, time.Duration(expiresIn)*time.Second, 0)
		},
		func() time.Duration { return 0 })

	configuredTTL := x.IfThenElseExec(f.ttl != nil,
		func() time.Duration { return *f.ttl },
		func() time.Duration { return 0 })

	switch {
	case configuredTTL == 0 && tokenEndpointResponseTTL == 0:
		return 0
	case configuredTTL == 0 && tokenEndpointResponseTTL != 0:
		return tokenEndpointResponseTTL
	case configuredTTL != 0 && tokenEndpointResponseTTL == 0:
		return configuredTTL
	default:
		return min(configuredTTL, tokenEndpointResponseTTL)
	}
}

func (f *oauth2ClientCredentialsFinalizer) isCacheEnabled() bool {
	// cache is enabled if it is not configured (in that case the ttl value from the
	// token response if used), or if it is configured and the value > 0
	return f.ttl == nil || (f.ttl != nil && *f.ttl > 0)
}
