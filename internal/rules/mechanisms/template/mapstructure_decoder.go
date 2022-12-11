package template

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
)

func DecodeTemplateHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var tpl Template

		if from.Kind() != reflect.String {
			return data, nil
		}

		dect := reflect.ValueOf(&tpl).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		switch data {
		case "":
			return nil, nil
		default:
			// nolint: forcetypeassert
			// already checked above
			return New(data.(string))
		}
	}
}
