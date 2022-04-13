package matcher

import (
	"net/url"
	"reflect"

	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/heimdall"
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
		for _, v := range data.([]any) {
			switch v {
			case "unauthorized":
				matcher = append(matcher, heimdall.ErrAuthentication)
			case "forbidden":
				matcher = append(matcher, heimdall.ErrAuthorization)
			case "internal_server_error":
				matcher = append(matcher, heimdall.ErrInternal)
				matcher = append(matcher, heimdall.ErrConfiguration)
			case "bad_argument":
				matcher = append(matcher, heimdall.ErrArgument)
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
