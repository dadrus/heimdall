package oauth2

import (
	"reflect"

	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/mitchellh/mapstructure"
)

func DecodeScopesMatcherHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var s ScopesMatcher

		if from.Kind() != reflect.Map && from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&s).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		if from.Kind() == reflect.Map {
			if m, ok := data.(map[string]any); ok {
				if name, ok := m["matching_strategy"]; ok {
					match, err := decodeStrategy(name.(string))
					if err != nil {
						return nil, err
					}

					s.Match = match
				}

				if values, ok := m["values"]; ok {
					copyScopeValues(&s, values)
				}
			} else if m, ok := data.(map[any]any); ok {
				if name, ok := m["matching_strategy"]; ok {
					match, err := decodeStrategy(name.(string))
					if err != nil {
						return nil, err
					}

					s.Match = match
				}

				if values, ok := m["values"]; ok {
					copyScopeValues(&s, values)
				}
			}

			s.Match = x.IfThenElse(s.Match != nil, s.Match, ExactScopeStrategy)

		} else if from.Kind() == reflect.Slice {
			s.Match = ExactScopeStrategy

			copyScopeValues(&s, data)
		} else {
			return nil, errorchain.NewWithMessage(ErrConfiguration, "invalid structure for scopes matcher")
		}

		if len(s.Scopes) == 0 {
			return nil, errorchain.NewWithMessage(ErrConfiguration, "scopes matcher configured, but no scopes provided")
		}

		return s, nil
	}
}

func copyScopeValues(s *ScopesMatcher, values any) {
	s.Scopes = make([]string, len(values.([]any)))
	for i, v := range values.([]any) {
		s.Scopes[i] = v.(string)
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
