package matcher

import (
	"net/url"
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func DecodeCIDRMatcherHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var matcher CIDRMatcher

		if from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&matcher).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		var cidrs []string

		// nolint: forcetypeassert
		for _, v := range data.([]any) {
			cidrs = append(cidrs, v.(string))
		}

		return NewCIDRMatcher(cidrs)
	}
}

func DecodeErrorTypeMatcherHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var matcher ErrorTypeMatcher

		if from.Kind() != reflect.Slice {
			return data, nil
		}

		dect := reflect.ValueOf(&matcher).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// nolint: forcetypeassert
		for _, val := range data.([]any) {
			switch val {
			case "authentication_error":
				matcher = append(matcher, heimdall.ErrAuthentication)
			case "authorization_error":
				matcher = append(matcher, heimdall.ErrAuthorization)
			case "internal_error":
				matcher = append(matcher, heimdall.ErrInternal)
				matcher = append(matcher, heimdall.ErrConfiguration)
			case "precondition_error":
				matcher = append(matcher, heimdall.ErrArgument)
			default:
				return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
					"unsupported error type: %s", val)
			}
		}

		return matcher, nil
	}
}

func StringToURLHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}

		if to != reflect.TypeOf(&url.URL{}) {
			return data, nil
		}

		// Convert it by parsing (type check is already done above)
		// nolint: forcetypeassert
		return url.Parse(data.(string))
	}
}
