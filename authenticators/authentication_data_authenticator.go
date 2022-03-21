package authenticators

import (
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/dadrus/heimdall/authenticators/extractors"
)

var _ Authenticator = new(authenticationDataAuthenticator)

func newAuthenticationDataAuthenticator(id string, rawConfig json.RawMessage) (*authenticationDataAuthenticator, error) {
	type config struct {
		Endpoint struct {
			Url    *url.URL `json:"url"`
			Method string   `json:"method"`
			Retry  struct {
				GiveUpAfter time.Duration `json:"give_up_after"`
				MaxDelay    time.Duration `json:"max_delay"`
			} `json:"retry"`
			Auth struct {
				Type   string          `json:"type"`
				Config json.RawMessage `json:"config"`
			} `json:"auth"`
		} `json:"identity_info_endpoint"`
		AuthInfoSource struct {
			Header         string `json:"header"`
			QueryParameter string `json:"query_parameter"`
			Cookie         string `json:"cookie"`
			StripPrefix    string `json:"strip_prefix"`
		} `json:"authentication_data_source"`
		Session struct {
			SubjectFrom string `json:"subject_from"`
			ExtraFrom   string `json:"extra_from"`
		} `json:"session"`
	}

	var c config
	if err := json.Unmarshal(rawConfig, &c); err != nil {
		return nil, err
	}

	var authDataExtractor extractors.AuthDataExtractor
	if len(c.AuthInfoSource.Cookie) != 0 {
		authDataExtractor = extractors.CookieExtractor(c.AuthInfoSource.Cookie)
	} else if len(c.AuthInfoSource.Header) != 0 {
		authDataExtractor = &extractors.HeaderExtractor{
			HeaderName: c.AuthInfoSource.Header, ValuePrefix: c.AuthInfoSource.StripPrefix,
		}
	} else if len(c.AuthInfoSource.QueryParameter) != 0 {
		authDataExtractor = extractors.QueryExtractor(c.AuthInfoSource.QueryParameter)
	} else {
		return nil, errors.New("missing auth data extractor")
	}

	return &authenticationDataAuthenticator{
		id:        id,
		extractor: authDataExtractor,
	}, nil
}

func createAuthDataExtractor() (extractors.AuthDataExtractor, error) {
	return nil, nil
}

type authenticationDataAuthenticator struct {
	id string

	extractor extractors.AuthDataExtractor
}

func (a *authenticationDataAuthenticator) Id() string {
	return a.id
}

func (a *authenticationDataAuthenticator) Authenticate() error {
	return nil
}
