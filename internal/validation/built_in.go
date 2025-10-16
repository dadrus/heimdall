package validation

import (
	"reflect"
)

type notAllowed struct{}

func (v notAllowed) Tag() string { return "not_allowed" }

func (v notAllowed) Validate(_ string, field reflect.Value) bool {
	switch field.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return field.IsNil()
	default:
		return false
	}
}

func (v notAllowed) AlwaysValidate() bool { return true }

func (v notAllowed) MessageTemplate() string { return "{0} {1}" }

func (v notAllowed) ErrorMessage(_ string) string { return "is not allowed" }
