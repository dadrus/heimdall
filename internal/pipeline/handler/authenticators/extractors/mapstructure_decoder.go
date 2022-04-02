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

		strategies = make(CompositeExtractStrategy, len(data.([]any)))
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
	var prefix string
	if p, ok := data["strip_prefix"]; ok {
		prefix = p.(string)
	}

	if v, ok := data["header"]; ok {
		return &HeaderValueExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["cookie"]; ok {
		return &CookieValueExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["query_parameter"]; ok {
		return &QueryParameterExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["form_parameter"]; ok {
		return &FormParameterExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "unsupported authentication source")
	}
}

func createStrategyFromStringAnyMap(data map[string]any) (AuthDataExtractStrategy, error) {
	var prefix string
	if p, ok := data["strip_prefix"]; ok {
		prefix = p.(string)
	}

	if v, ok := data["header"]; ok {
		return &HeaderValueExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["cookie"]; ok {
		return &CookieValueExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["query_parameter"]; ok {
		return &QueryParameterExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else if v, ok := data["form_parameter"]; ok {
		return &FormParameterExtractStrategy{Name: v.(string), Prefix: prefix}, nil
	} else {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "unsupported authentication source")
	}
}
