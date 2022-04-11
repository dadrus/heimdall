package errorhandlers

import (
	"net"
	"reflect"

	"github.com/mitchellh/mapstructure"
	"github.com/yl2chen/cidranger"

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

		ranger := cidranger.NewPCTrieRanger()

		// nolint: forcetypeassert
		for _, v := range data.([]any) {
			// nolint
			_, ipNet, err := net.ParseCIDR(v.(string))
			if err != nil {
				return nil, err
			}

			if err := ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet)); err != nil {
				return nil, err
			}
		}

		return &CIDRMatcher{r: ranger}, nil
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
