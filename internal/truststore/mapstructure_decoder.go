package truststore

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
)

func DecodeTrustStoreHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var trustStore TrustStore

		if from.Kind() != reflect.String {
			return data, nil
		}

		dect := reflect.ValueOf(&trustStore).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// nolint: forcetypeassert
		// already checked above
		return NewTrustStoreFromPEMFile(data.(string))
	}
}
