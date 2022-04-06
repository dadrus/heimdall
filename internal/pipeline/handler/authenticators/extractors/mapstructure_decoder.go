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
			} else if values, ok := entry.(map[string]any); ok {
				strategy, err := createStrategyFromStringAnyMap(values)
				if err != nil {
					return data, err
				}

				strategies[i] = strategy
			}
		}

		return strategies, nil
	}
}

func createStrategyFromAnyAnyMap(data map[any]any) (AuthDataExtractStrategy, error) {
	if v, ok := data["header"]; ok {
		var prefix string
		if p, ok := data["strip_prefix"]; ok {
			// nolint
			// ok if panics
			prefix = p.(string)
		}
		// nolint
		// ok if panics
		return &HeaderValueExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["cookie"]; ok {
		// nolint
		// ok if panics
		return &CookieValueExtractStrategy{Name: v.(string)}, nil
	} else if v, ok := data["query_parameter"]; ok {
		// nolint
		// ok if panics
		return &QueryParameterExtractStrategy{Name: v.(string)}, nil
	} else {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "unsupported authentication source")
	}
}

func createStrategyFromStringAnyMap(data map[string]any) (AuthDataExtractStrategy, error) {
	if v, ok := data["header"]; ok {
		var prefix string
		if p, ok := data["strip_prefix"]; ok {
			// nolint
			// ok if panics
			prefix = p.(string)
		}

		// nolint
		// ok if panics
		return &HeaderValueExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["cookie"]; ok {
		// nolint
		// ok if panics
		return &CookieValueExtractStrategy{Name: v.(string)}, nil
	} else if v, ok := data["query_parameter"]; ok {
		// nolint
		// ok if panics
		return &QueryParameterExtractStrategy{Name: v.(string)}, nil
	} else {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "unsupported authentication source")
	}
}
