package endpoint

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func NewAuthenticationStrategy(name string, conf map[string]interface{}) (AuthenticationStrategy, error) {
	switch name {
	case "":
		return &NoopAuthStrategy{}, nil
	case "basic":
		var strategy BasicAuthStrategy
		// err := yaml.UnmarshalStrict(conf, &strategy)

		return &strategy, nil
	case "api_key":
		var strategy APIKeyStrategy
		// err := yaml.UnmarshalStrict(conf, &strategy)

		return &strategy, nil
	case "client_credentials":
		var strategy ClientCredentialsStrategy
		// err := yaml.UnmarshalStrict(conf, &strategy)

		return &strategy, nil
	default:
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "\"%s\" authentication type unsupported", name)
	}
}
