package finalizers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
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

type AuthMethod string

const (
	authMethodBasicAuth   AuthMethod = "basic_auth"
	authMethodRequestBody AuthMethod = "request_body"
)

type TokenSuccessfulResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int64  `json:"expires_in,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

type TokenErrorResponse struct { //nolint:errname
	ErrorType        string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

func (e *TokenErrorResponse) Error() string {
	builder := strings.Builder{}
	builder.WriteString("error from oauth2 server: ")
	builder.WriteString("error: ")
	builder.WriteString(e.ErrorType)

	if len(e.ErrorDescription) != 0 {
		builder.WriteString(", error_description: ")
		builder.WriteString(e.ErrorDescription)
	}

	if len(e.ErrorURI) != 0 {
		builder.WriteString(", error_uri: ")
		builder.WriteString(e.ErrorURI)
	}

	return builder.String()
}

type TokenEndpointResponse struct {
	*TokenSuccessfulResponse
	*TokenErrorResponse
}

func (r TokenEndpointResponse) Error() error {
	// weird go behavior
	if r.TokenErrorResponse != nil {
		return r.TokenErrorResponse
	}

	return nil
}

type oauth2ClientCredentialsFinalizer struct {
	id           string
	tokenURL     string
	clientID     string
	clientSecret string
	authMethod   AuthMethod
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
		AuthMethod   AuthMethod     `mapstructure:"auth_method"   validate:"omitempty,oneof=basic_auth request_body"`
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
		authMethod:   x.IfThenElse(len(conf.AuthMethod) == 0, authMethodBasicAuth, conf.AuthMethod),
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
		authMethod:   f.authMethod,
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
		cacheKey   string
		cacheEntry any
		token      string
	)

	if f.isCacheEnabled() {
		cacheKey = f.calculateCacheKey()
		cacheEntry = cch.Get(cacheKey)
	}

	if cacheEntry != nil {
		if token, ok = cacheEntry.(string); !ok {
			logger.Warn().Msg("Wrong object type from cache")
			cch.Delete(cacheKey)
		} else {
			logger.Debug().Msg("Reusing access token from cache")
		}
	}

	if len(token) == 0 {
		logger.Debug().Msg("Retrieving new access token")

		tokenInfo, err := f.getAccessToken(ctx.AppContext())
		if err != nil {
			return err
		}

		token = tokenInfo.AccessToken

		if cacheTTL := f.getCacheTTL(tokenInfo); cacheTTL > 0 {
			cch.Set(cacheKey, token, cacheTTL)
		}
	}

	ctx.AddHeaderForUpstream(f.headerName, fmt.Sprintf("%s %s", f.headerScheme, token))

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

func (f *oauth2ClientCredentialsFinalizer) getAccessToken(ctx context.Context) (*TokenSuccessfulResponse, error) {
	ept := endpoint.Endpoint{
		URL:          f.tokenURL,
		Method:       http.MethodPost,
		AuthStrategy: f.authStrategy(),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Accept-Type":  "application/json",
		},
	}

	data := url.Values{"grant_type": []string{"client_credentials"}}
	if len(f.scopes) != 0 {
		data.Add("scope", strings.Join(f.scopes, " "))
	}

	// This is not recommended, but there are non-compliant servers out there
	// which do not support the Basic Auth authentication method required by
	// the spec. See also https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
	if ept.AuthStrategy == nil {
		data.Add("client_id", f.clientID)
		data.Add("client_secret", f.clientSecret)
	}

	rawData, err := ept.SendRequest(
		ctx,
		strings.NewReader(data.Encode()),
		nil,
		func(resp *http.Response) ([]byte, error) {
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
				return nil, errorchain.NewWithMessagef(heimdall.ErrCommunication,
					"unexpected response code: %v", resp.StatusCode)
			}

			rawData, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
					"failed to read response").CausedBy(err)
			}

			if resp.StatusCode == http.StatusBadRequest {
				var ter TokenErrorResponse
				if err := json.Unmarshal(rawData, &ter); err != nil {
					return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
						"failed to unmarshal response").CausedBy(err)
				}

				return nil, errorchain.New(heimdall.ErrCommunication).CausedBy(&ter)
			}

			return rawData, nil
		},
	)
	if err != nil {
		return nil, err
	}

	// some oauth2 provider are not compliant and return errors via HTTP 200 instead of 400
	// this is the reason for using a union struct here (see the error check below)
	var resp TokenEndpointResponse
	if err := json.Unmarshal(rawData, &resp); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to unmarshal response").CausedBy(err)
	}

	if resp.Error() != nil {
		return nil, errorchain.New(heimdall.ErrCommunication).CausedBy(resp.Error())
	}

	return resp.TokenSuccessfulResponse, nil
}

func (f *oauth2ClientCredentialsFinalizer) authStrategy() endpoint.AuthenticationStrategy {
	if f.authMethod == authMethodRequestBody {
		return nil
	}

	return &endpoint.BasicAuthStrategy{
		User:     url.QueryEscape(f.clientID),
		Password: url.QueryEscape(f.clientSecret),
	}
}

func (f *oauth2ClientCredentialsFinalizer) getCacheTTL(resp *TokenSuccessfulResponse) time.Duration {
	// timeLeeway defines the default time deviation to ensure the token is still valid
	// when used from cache
	const timeLeeway = 5

	if !f.isCacheEnabled() {
		return 0
	}

	// we cache by default using the settings in the token endpoint response (if available)
	// or if ttl has been configured. Latter overwrites the settings in the token endpoint response
	// if it is shorter than the ttl in the token endpoint response
	tokenEndpointResponseTTL := x.IfThenElseExec(resp.ExpiresIn != 0,
		func() time.Duration {
			expiresIn := resp.ExpiresIn - timeLeeway

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
