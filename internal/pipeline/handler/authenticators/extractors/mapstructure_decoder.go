package extractors

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeCompositeExtractStrategyHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		var strategies CompositeExtractStrategy

		if from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&strategies).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		for _, entry := range data.([]interface{}) {
			values, ok := entry.(map[interface{}]interface{})
			if !ok {
				return data, nil
			}

			strategy, err := createStrategy(values)
			if err != nil {
				return data, err
			}

			strategies = append(strategies, strategy)
		}

		return strategies, nil
	}
}

func createStrategy(data map[interface{}]interface{}) (AuthDataExtractStrategy, error) {
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
