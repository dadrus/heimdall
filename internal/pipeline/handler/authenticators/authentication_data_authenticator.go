package authenticators

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func init() {
	handler.RegisterAuthenticatorTypeFactory(
		func(typ config.PipelineObjectType, conf map[string]any) (bool, handler.Authenticator, error) {
			if typ != config.POTAuthenticationData {
				return false, nil, nil
			}

			auth, err := newAuthenticationDataAuthenticator(conf)

			return true, auth, err
		})
}

type authenticationDataAuthenticator struct {
	e   Endpoint
	se  SubjectExtrator
	adg extractors.AuthDataExtractStrategy
}

func newAuthenticationDataAuthenticator(rawConfig map[string]any) (*authenticationDataAuthenticator, error) {
	type _config struct {
		Endpoint       endpoint.Endpoint                   `mapstructure:"identity_info_endpoint"`
		AuthDataSource extractors.CompositeExtractStrategy `mapstructure:"authentication_data_source"`
		Session        Session                             `mapstructure:"session"`
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
	}, nil
}

func (a *authenticationDataAuthenticator) Authenticate(ctx heimdall.Context) (*subject.Subject, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	logger.Debug().Msg("Retrieving authentication data from request")

	authData, err := a.adg.GetAuthData(ctx)
	if err != nil {
		return nil, errorchain.New(heimdall.ErrAuthentication).CausedBy(err)
	}

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

	payload, err := a.readResponse(resp)
	if err != nil {
		return nil, err
	}

	sub, err := a.se.GetSubject(payload)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to extract subject information from response").
			CausedBy(err)
	}

	return sub, nil
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

func (a *authenticationDataAuthenticator) WithConfig(_ map[string]any) (handler.Authenticator, error) {
	// this authenticator does not allow configuration from a rule
	return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "reconfiguration not allowed")
}
