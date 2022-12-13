package endpoint

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeEndpointHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var ep Endpoint

		if from.Kind() != reflect.String {
			return data, nil
		}

		dect := reflect.ValueOf(&ep).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// Already checked above
		// nolint: forcetypeassert
		return Endpoint{URL: data.(string)}, nil
	}
}

func DecodeAuthenticationStrategyHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var as AuthenticationStrategy

		if from.Kind() != reflect.Map {
			return data, nil
		}

		dect := reflect.ValueOf(&as).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		typed := map[string]any{}

		if m, ok := data.(map[any]any); ok {
			for k, v := range m {
				// nolint: forcetypeassert
				// ok if panics
				typed[k.(string)] = v
			}
		} else if m, ok := data.(map[string]any); ok {
			typed = m
		} else {
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration, "unexpected configuration type")
		}

		switch typed["type"] {
		case "basic_auth":
			return decodeBasicAuthStrategy(typed["config"])
		case "api_key":
			return decodeAPIKeyStrategy(typed["config"])
		case "client_credentials":
			return decodeClientCredentialsStrategy(typed["config"])
		default:
			return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
				"unsupported authentication type: '%s'", typed["type"])
		}
	}
}

func decodeClientCredentialsStrategy(config any) (AuthenticationStrategy, error) {
	var strategy ClientCredentialsStrategy

	if config == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"client-credentials strategy requires 'config' property to be set")
	}

	err := mapstructure.Decode(config, &strategy)
	if err != nil {
		return nil, err
	}

	if len(strategy.ClientID) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"client-credentials strategy requires 'client_id' property to be set")
	}

	if len(strategy.ClientSecret) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"client-credentials strategy requires 'client_secret' property to be set")
	}

	if len(strategy.TokenURL) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"client-credentials strategy requires 'token_url' property to be set")
	}

	return &strategy, nil
}

func decodeAPIKeyStrategy(config any) (AuthenticationStrategy, error) {
	var strategy APIKeyStrategy

	if config == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"api-key strategy requires 'config' property to be set")
	}

	err := mapstructure.Decode(config, &strategy)
	if err != nil {
		return nil, err
	}

	if len(strategy.Name) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"api-key strategy requires 'name' property to be set")
	}

	if len(strategy.Value) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"api-key strategy requires 'value' property to be set")
	}

	if len(strategy.In) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"api-key strategy requires 'in' property to be set")
	}

	if strategy.In != "header" && strategy.In != "cookie" {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"api-key strategy requires 'in' property to be set to either 'header' or 'cookie'")
	}

	return &strategy, nil
}

func decodeBasicAuthStrategy(config any) (AuthenticationStrategy, error) {
	var strategy BasicAuthStrategy

	if config == nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"basic-auth strategy requires 'config' property to be set")
	}

	err := mapstructure.Decode(config, &strategy)
	if err != nil {
		return nil, err
	}

	if len(strategy.User) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"basic-auth strategy requires 'user' property to be set")
	}

	if len(strategy.Password) == 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"basic-auth strategy requires 'password' property to be set")
	}

	return &strategy, nil
}
