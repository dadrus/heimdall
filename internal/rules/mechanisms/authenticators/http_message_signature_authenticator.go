package authenticators

import (
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/truststore"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/go-jose/go-jose/v4"
	"github.com/goccy/go-json"
)

func init() {
	registerTypeFactory(
		func(app app.Context, name string, typ string, conf map[string]any) (bool, Authenticator, error) {
			if typ != AuthenticatorHTTPMessageSignatures {
				return false, nil, nil
			}

			auth, err := newHTTPMessageSignaturesAuthenticator(app, name, conf)

			return true, auth, err
		})
}

type JWKResolver interface {
	GetJSONWebKey(ctx heimdall.RequestContext) (jose.JSONWebKey, error)
}

type JWKSEndpointResolver struct {
	ep *endpoint.Endpoint
}

func (r *JWKSEndpointResolver) GetJSONWebKey(ctx heimdall.RequestContext) (jose.JSONWebKey, error) {
	data, err := r.ep.SendRequest(ctx.Context(), nil, nil, nil)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	var key jose.JSONWebKey

	if err = json.Unmarshal(data, &key); err != nil {
		return jose.JSONWebKey{}, err
	}

	return key, nil
}

type SignatureAgentBasedResolver struct{}

func (r *SignatureAgentBasedResolver) GetJSONWebKey(ctx heimdall.RequestContext) (jose.JSONWebKey, error) {
	value := ctx.Request().Header("Signature-Agent")
	if len(value) == 0 {
		return jose.JSONWebKey{}, errors.New("no signature agent header")
	}

	uri, err := url.Parse(value)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if uri.Scheme == "http" || uri.Scheme == "https" {
		return r.fetchKey(ctx, uri)
	} else if uri.Scheme == "data" {
		return r.extractKey(uri)
	}

	return jose.JSONWebKey{}, errors.New("no signature agent header")
}

func (r *SignatureAgentBasedResolver) extractKey(uri *url.URL) (jose.JSONWebKey, error) {
	// data:application/http-message-signatures-directory+json[;base64],<data>
	values := strings.Split(uri.Opaque, ",")
	if len(values) != 2 {
		return jose.JSONWebKey{}, errors.New("mime: malformed data")
	}

	mediatype, params, err := mime.ParseMediaType(values[0])
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if mediatype != "application/http-message-signatures-directory+json" {
		return jose.JSONWebKey{}, errors.New("mediatype not supported")
	}

	var (
		reader io.Reader
		key    jose.JSONWebKey
	)

	if _, ok := params["base64"]; ok {
		reader = base64.NewDecoder(base64.StdEncoding, strings.NewReader(values[1]))
	} else {
		reader = strings.NewReader(values[1])
	}

	if err = json.NewDecoder(reader).Decode(&key); err != nil {
		return jose.JSONWebKey{}, err
	}

	return key, nil
}

func (r *SignatureAgentBasedResolver) fetchKey(ctx heimdall.RequestContext, uri *url.URL) (jose.JSONWebKey, error) {
	epr := JWKSEndpointResolver{
		ep: &endpoint.Endpoint{
			URL:    uri.String(),
			Method: http.MethodGet,
			Headers: map[string]string{
				"Accept": "application/json",
			},
			HTTPCache: &endpoint.HTTPCache{
				Enabled:    true,
				DefaultTTL: 5 * time.Minute,
			},
		},
	}

	return epr.GetJSONWebKey(ctx)
}

type httpMessageSignaturesAuthenticator struct {
	name               string
	id                 string
	app                app.Context
	components         []string
	jwkr               JWKResolver
	tofuAllowed        bool
	sigCreatedDateSkew time.Duration
	maxAge             time.Duration
	ttl                *time.Duration
	validateJWKCert    bool
	trustStore         truststore.TrustStore
}

func newHTTPMessageSignaturesAuthenticator(app app.Context, name string, rawConfig map[string]any) (Authenticator, error) {
	logger := app.Logger()
	logger.Info().
		Str("_type", AuthenticatorHTTPMessageSignatures).
		Str("_name", name).
		Msg("Creating authenticator")

	type TaggedSignature struct {
		Tag        string   `mapstructure:"tag"        validate:"required"`
		Components []string `mapstructure:"components" validate:"gt=0,dive,required"`
	}

	type Config struct {
		RequiredComponents []string              `mapstructure:"required_components"            validate:"gt=0,dive,required"`         //nolint:lll
		TOFUKeyAllowed     *bool                 `mapstructure:"trust_key_on_first_use_allowed" validate:"excluded_with=JWKSEndpoint"` //nolint:lll
		JWKSEndpoint       *endpoint.Endpoint    `mapstructure:"jwks_endpoint"                  validate:"excluded_with=TOFUAllowed"`  //nolint:lll
		MaxAge             *time.Duration        `mapstructure:"max_age"`
		Skew               time.Duration         `mapstructure:"skew"`
		CacheTTL           *time.Duration        `mapstructure:"cache_ttl"`
		ValidateJWK        *bool                 `mapstructure:"validate_jwk"`
		TrustStore         truststore.TrustStore `mapstructure:"trust_store"`
	}

	var conf Config
	if err := decodeConfig(app, rawConfig, &conf); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed decoding config for %s authenticator '%s'", AuthenticatorHTTPMessageSignatures, name).
			CausedBy(err)
	}

	var jwkr JWKResolver

	if conf.JWKSEndpoint != nil {
		if strings.HasPrefix(conf.JWKSEndpoint.URL, "http://") {
			logger.Warn().
				Str("_type", AuthenticatorJWT).
				Str("_name", name).
				Msg("No TLS configured for the jwks endpoint used in authenticator")
		}

		jwkr = &SignatureAgentBasedResolver{}
	} else {
		ep := conf.JWKSEndpoint

		if ep.Headers == nil {
			ep.Headers = make(map[string]string)
		}

		if _, ok := ep.Headers["Accept"]; !ok {
			ep.Headers["Accept"] = "application/json"
		}

		if len(ep.Method) == 0 {
			ep.Method = http.MethodGet
		}

		jwkr = &JWKSEndpointResolver{ep: ep}
	}

	return &httpMessageSignaturesAuthenticator{
		name:       name,
		id:         name,
		app:        app,
		components: conf.Components,
		jwkr:       jwkr,
		tofuAllowed: x.IfThenElseExec(
			conf.TOFUKeyAllowed != nil,
			func() bool { return *conf.TOFUKeyAllowed },
			func() bool { return false }),
		sigCreatedDateSkew: conf.Skew,
		maxAge: x.IfThenElseExec(
			conf.MaxAge != nil,
			func() time.Duration { return *conf.MaxAge },
			func() time.Duration { return 5 * time.Minute },
		),
		ttl: conf.CacheTTL,
		validateJWKCert: x.IfThenElseExec(
			conf.ValidateJWK != nil,
			func() bool { return *conf.ValidateJWK },
			func() bool { return true },
		),
		trustStore: conf.TrustStore,
	}, nil
}

func (a *httpMessageSignaturesAuthenticator) ID() string { return a.id }

func (a *httpMessageSignaturesAuthenticator) IsInsecure() bool { return false }

func (a *httpMessageSignaturesAuthenticator) Execute(ctx heimdall.RequestContext) (*subject.Subject, error) {
	//TODO implement me
	panic("implement me")
}

func (a *httpMessageSignaturesAuthenticator) WithConfig(stepID string, config map[string]any) (Authenticator, error) {
	//TODO implement me
	panic("implement me")
}

func (a *httpMessageSignaturesAuthenticator) isCacheEnabled() bool {
	// cache is enabled if ttl is not configured (in that case the ttl value from either
	// the jwk cert (if available) or the defaultTTL is used), or if ttl is configured and
	// the value > 0
	return a.ttl == nil || (a.ttl != nil && *a.ttl > 0)
}
