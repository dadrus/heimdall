package endpoint

import (
	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func NewAuthenticationStrategy(name string, conf []byte) (AuthenticationStrategy, error) {
	switch name {
	case "":
		return &NoopAuthStrategy{}, nil
	case "basic":
		var strategy BasicAuthStrategy
		err := yaml.UnmarshalStrict(conf, &strategy)

		return &strategy, err
	case "api_key":
		var strategy APIKeyStrategy
		err := yaml.UnmarshalStrict(conf, &strategy)

		return &strategy, err
	case "client_credentials":
		var strategy ClientCredentialsStrategy
		err := yaml.UnmarshalStrict(conf, &strategy)

		return &strategy, err
	default:
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "\"%s\" authentication type unsupported", name)
	}
}
