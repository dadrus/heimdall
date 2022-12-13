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
		var matcher ErrorDescriptor

		if from.Kind() != reflect.Map {
			return data, nil
		}

		dect := reflect.ValueOf(&matcher).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// already checked above
		// nolint: forcetypeassert
		conf := data.(map[string]any)
		switch conf["type"] {
		case "authentication_error":
			matcher.Errors = []error{heimdall.ErrAuthentication}
		case "authorization_error":
			matcher.Errors = []error{heimdall.ErrAuthorization}
		case "internal_error":
			matcher.Errors = []error{heimdall.ErrInternal, heimdall.ErrConfiguration}
		case "precondition_error":
			matcher.Errors = []error{heimdall.ErrArgument}
		default:
			return ErrorDescriptor{}, errorchain.
				NewWithMessagef(heimdall.ErrConfiguration, "unsupported error type: %s", conf["type"])
		}

		if src, ok := conf["raised_by"]; ok {
			if matcher.HandlerID, ok = src.(string); !ok {
				return ErrorDescriptor{}, errorchain.
					NewWithMessage(heimdall.ErrConfiguration, "raised_by must be a string")
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
