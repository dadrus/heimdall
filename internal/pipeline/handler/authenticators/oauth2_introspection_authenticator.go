package authenticators

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type oauth2IntrospectionAuthenticator struct {
	e   Endpoint
	a   oauth2.Expectation
	se  SubjectExtrator
	adg AuthDataGetter
}

func NewOAuth2IntrospectionAuthenticatorFromYAML(rawConfig json.RawMessage) (*oauth2IntrospectionAuthenticator, error) {
	type _config struct {
		Endpoint   endpoint.Endpoint  `yaml:"introspection_endpoint"`
		Assertions oauth2.Expectation `yaml:"introspection_response_assertions"`
		Session    Session            `yaml:"session"`
	}

	var conf _config
	if err := yaml.UnmarshalStrict(rawConfig, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to unmarshal oauth2 introspection authenticator config").
			CausedBy(err)
	}

	if len(conf.Assertions.AllowedAlgorithms) == 0 {
		conf.Assertions.AllowedAlgorithms = []string{
			// ECDSA
			string(jose.ES256), string(jose.ES384), string(jose.ES512),
			// RSA-PSS
			string(jose.PS256), string(jose.PS384), string(jose.PS512),
		}
	}

	if err := conf.Assertions.Validate(); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to validate assertions configuration").
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
		conf.Endpoint.Method = "POST"
	}

	extractor := extractors.CompositeExtractStrategy{
		extractors.HeaderValueExtractStrategy{Name: "Authorization", Prefix: "Bearer"},
		extractors.FormParameterExtractStrategy{Name: "access_token"},
		extractors.QueryParameterExtractStrategy{Name: "access_token"},
	}

	return &oauth2IntrospectionAuthenticator{
		adg: extractor,
		e:   conf.Endpoint,
		a:   conf.Assertions,
		se:  &conf.Session,
	}, nil
}

func (a *oauth2IntrospectionAuthenticator) Authenticate(
	ctx context.Context,
	as handler.RequestContext,
	sc *heimdall.SubjectContext,
) error {
	accessToken, err := a.adg.GetAuthData(as)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no access token present").
			CausedBy(err)
	}

	rawBody, err := a.e.SendRequest(ctx, strings.NewReader(
		url.Values{
			"token":           []string{accessToken},
			"token_type_hint": []string{"access_token"},
		}.Encode()),
	)
	if err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrCommunicationTimeout, "request to the introspection endpoint failed").
			CausedBy(err)
	}

	var resp oauth2.IntrospectionResponse
	if err = json.Unmarshal(rawBody, &resp); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to unmarshal received introspection response").
			CausedBy(err)
	}

	if err = resp.Validate(a.a); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "access token does not satisfy assertion conditions").
			CausedBy(err)
	}

	if sc.Subject, err = a.se.GetSubject(rawBody); err != nil {
		return errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from introspection response").
			CausedBy(err)
	}

	return nil
}

func (a *oauth2IntrospectionAuthenticator) WithConfig(config []byte) (handler.Authenticator, error) {
	// this authenticator allows assertions to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		Assertions oauth2.Expectation `yaml:"introspection_response_assertions"`
	}

	var conf _config
	if err := yaml.UnmarshalStrict(config, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to parse configuration").
			CausedBy(err)
	}

	return &oauth2IntrospectionAuthenticator{
		e:   a.e,
		a:   conf.Assertions,
		se:  a.se,
		adg: a.adg,
	}, nil
}
