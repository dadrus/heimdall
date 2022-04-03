package oauth2

import (
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeScopesMatcherHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var matcher ScopesMatcher

		if from.Kind() != reflect.Map && from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&matcher).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// nolint
		// we care about these two cases only
		switch from.Kind() {
		case reflect.Map:
			// nolint
			if m, ok := data.(map[string]any); ok {
				if name, ok := m["matching_strategy"]; ok {
					match, err := decodeStrategy(name.(string))
					if err != nil {
						return nil, err
					}

					matcher.Match = match
				}

				if values, ok := m["values"]; ok {
					copyScopeValues(&matcher, values)
				}
			} else if m, ok := data.(map[any]any); ok {
				if name, ok := m["matching_strategy"]; ok {
					match, err := decodeStrategy(name.(string))
					if err != nil {
						return nil, err
					}

					matcher.Match = match
				}

				if values, ok := m["values"]; ok {
					copyScopeValues(&matcher, values)
				}
			}

			matcher.Match = x.IfThenElse(matcher.Match != nil, matcher.Match, ExactScopeStrategy)
		case reflect.Slice:
			matcher.Match = ExactScopeStrategy

			copyScopeValues(&matcher, data)
		default:
			return nil, errorchain.NewWithMessage(ErrConfiguration, "invalid structure for scopes matcher")
		}

		if len(matcher.Scopes) == 0 {
			return nil, errorchain.NewWithMessage(ErrConfiguration, "scopes matcher configured, but no scopes provided")
		}

		return matcher, nil
	}
}

func copyScopeValues(matcher *ScopesMatcher, values any) {
	// nolint
	matcher.Scopes = make([]string, len(values.([]any)))
	// nolint
	for i, v := range values.([]any) {
		// nolint
		matcher.Scopes[i] = v.(string)
	}
}

func decodeStrategy(name string) (ScopesMatcherFunc, error) {
	switch name {
	case "exact":
		return ExactScopeStrategy, nil
	case "hierarchic":
		return HierarchicScopeStrategy, nil
	case "wildcard":
		return WildcardScopeStrategy, nil
	default:
		return nil, errorchain.NewWithMessagef(ErrConfiguration, "unsupported strategy \"%s\"", name)
	}
}
