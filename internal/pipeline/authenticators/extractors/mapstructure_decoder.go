package extractors

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeCompositeExtractStrategyHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var strategies CompositeExtractStrategy

		if from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&strategies).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// nolint
		// already checked above
		strategies = make(CompositeExtractStrategy, len(data.([]any)))

		// nolint
		// already checked above
		for i, entry := range data.([]any) {
			if values, ok := entry.(map[any]any); ok {
				strategy, err := createStrategyFromAnyAnyMap(values)
				if err != nil {
					return data, err
				}

				strategies[i] = strategy
			} else {
				return nil, errorchain.
					NewWithMessage(heimdall.ErrInternal, "unexpected authentication config type")
			}
		}

		return strategies, nil
	}
}

func createStrategyFromAnyAnyMap(data map[any]any) (AuthDataExtractStrategy, error) {
	if value, ok := data["header"]; ok {
		var prefix string
		if p, ok := data["strip_prefix"]; ok {
			// nolint
			// ok if panics
			prefix = p.(string)
		}
		// nolint
		// ok if panics
		return &HeaderValueExtractStrategy{Name: value.(string), Prefix: prefix}, nil
	} else if value, ok := data["cookie"]; ok {
		// nolint
		// ok if panics
		return &CookieValueExtractStrategy{Name: value.(string)}, nil
	} else if value, ok := data["query_parameter"]; ok {
		// nolint
		// ok if panics
		return &QueryParameterExtractStrategy{Name: value.(string)}, nil
	} else {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "unsupported authentication source")
	}
}
