package authenticators

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/square/go-jose.v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

// by intention. Used only during application bootstrap
// nolint
func init() {
	handler.RegisterAuthenticatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, handler.Authenticator, error) {
			if typ != config.POTOAuth2Introspection {
				return false, nil, nil
			}

			auth, err := newOAuth2IntrospectionAuthenticator(conf)

			return true, auth, err
		})
}

type oauth2IntrospectionAuthenticator struct {
	e   Endpoint
	a   oauth2.Expectation
	se  SubjectExtrator
	adg extractors.AuthDataExtractStrategy
}

func newOAuth2IntrospectionAuthenticator(rawConfig map[string]any) (*oauth2IntrospectionAuthenticator, error) {
	type _config struct {
		Endpoint   endpoint.Endpoint  `mapstructure:"introspection_endpoint"`
		Assertions oauth2.Expectation `mapstructure:"introspection_response_assertions"`
		Session    Session            `mapstructure:"session"`
	}

	var conf _config
	if err := decodeConfig(rawConfig, &conf); err != nil {
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
		extractors.CookieValueExtractStrategy{Name: "access_token"},
		extractors.QueryParameterExtractStrategy{Name: "access_token"},
	}

	return &oauth2IntrospectionAuthenticator{
		adg: extractor,
		e:   conf.Endpoint,
		a:   conf.Assertions,
		se:  &conf.Session,
	}, nil
}

func (a *oauth2IntrospectionAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	accessToken, err := a.adg.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "no access token present").
			CausedBy(err)
	}

	req, err := a.e.CreateRequest(ctx.AppContext(), strings.NewReader(
		url.Values{
			"token":           []string{accessToken.Value()},
			"token_type_hint": []string{"access_token"},
		}.Encode()))
	if err != nil {
		return nil, err
	}

	resp, err := a.e.CreateClient().Do(req)
	if err != nil {
		var clientErr *url.Error
		if errors.As(err, &clientErr) && clientErr.Timeout() {
			return nil, errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout,
				"request to the introspection endpoint timed out").CausedBy(err)
		}

		return nil, errorchain.NewWithMessage(heimdall.ErrCommunication,
			"request to the introspection endpoint failed").CausedBy(err)
	}

	defer resp.Body.Close()

	introspectResp, rawResp, err := a.readIntrospectionResponse(resp)
	if err != nil {
		return nil, err
	}

	if err = introspectResp.Validate(a.a); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrAuthentication, "access token does not satisfy assertion conditions").
			CausedBy(err)
	}

	sub, err := a.se.GetSubject(rawResp)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from introspection response").
			CausedBy(err)
	}

	return sub, nil
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
		NewWithMessagef(heimdall.ErrCommunication, "unexpected response. code: %v", resp.StatusCode)
}

func (a *oauth2IntrospectionAuthenticator) WithConfig(config map[string]any) (handler.Authenticator, error) {
	// this authenticator allows assertions to be redefined on the rule level
	if len(config) == 0 {
		return a, nil
	}

	type _config struct {
		Assertions oauth2.Expectation `mapstructure:"introspection_response_assertions"`
	}

	var conf _config
	if err := mapstructure.Decode(config, &conf); err != nil {
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
