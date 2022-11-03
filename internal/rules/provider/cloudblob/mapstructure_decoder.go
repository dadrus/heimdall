package cloudblob

import (
	"net/url"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

func urlDecodeHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var exp *url.URL

		dect := reflect.ValueOf(&exp).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		if from.Kind() != reflect.String {
			return data, nil
		}

		// nolint: forcetypeassert
		return url.Parse(data.(string)) // already checked above
	}
}
