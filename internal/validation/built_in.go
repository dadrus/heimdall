package validation

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
)

type notAllowedValidator struct{}

func (v notAllowedValidator) Tag() string                  { return "not_allowed" }
func (v notAllowedValidator) AlwaysValidate() bool         { return true }
func (v notAllowedValidator) MessageTemplate() string      { return "{0} {1}" }
func (v notAllowedValidator) ErrorMessage(_ string) string { return "is not allowed" }

func (v notAllowedValidator) Validate(_ string, field reflect.Value) bool {
	switch field.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return field.IsNil()
	default:
		return false
	}
}

type urlValidator struct{}

func (v urlValidator) Tag() string                  { return "url" }
func (v urlValidator) AlwaysValidate() bool         { return false }
func (v urlValidator) MessageTemplate() string      { return "{0} {1}" }
func (v urlValidator) ErrorMessage(_ string) string { return "must be a valid URL" }

func (v urlValidator) Validate(_ string, field reflect.Value) bool {
	if !field.IsValid() {
		return false
	}

	var raw string

	switch v := field.Interface().(type) {
	case string:
		raw = v
	case fmt.Stringer:
		raw = v.String()
	default:
		return false
	}

	raw = strings.ToLower(raw)

	if len(raw) == 0 {
		return false
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return false
	}

	isFileScheme := parsed.Scheme == "file"

	if (isFileScheme && (len(parsed.Path) == 0 || parsed.Path == "/")) ||
		(!isFileScheme && len(parsed.Host) == 0 && len(parsed.Fragment) == 0 && len(parsed.Opaque) == 0) {
		return false
	}

	return true
}
