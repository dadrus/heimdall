package validation

import (
	"reflect"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

type TagValidator interface {
	// Tag returns the identifier of the custom validator.
	Tag() string
	// Validate implements the actual validation logic.
	Validate(param string, field reflect.Value) bool
	// AlwaysValidate informs that the Validate function
	// should always be called, even if the field is not set
	AlwaysValidate() bool
}

type ErrorTranslator interface {
	// Tag returns the identifier of the tag this translator is for.
	Tag() string
	// MessageTemplate returns a template for error translation
	MessageTemplate() string
	// ErrorMessage provides an error message for the given param.
	ErrorMessage(param string) string
}

type TagNameSupplier interface {
	TagName(sf reflect.StructField) string
}

type TagNameSupplierFunc func(sf reflect.StructField) string

func (f TagNameSupplierFunc) TagName(sf reflect.StructField) string {
	return f(sf)
}

type Option interface {
	apply(v *validator.Validate, t ut.Translator) error
}

type optionFunc func(v *validator.Validate, t ut.Translator) error

func (f optionFunc) apply(v *validator.Validate, t ut.Translator) error {
	return f(v, t)
}

func WithTagValidator(tv TagValidator) Option {
	return optionFunc(func(v *validator.Validate, _ ut.Translator) error {
		err := v.RegisterValidation(
			tv.Tag(),
			func(fl validator.FieldLevel) bool { return tv.Validate(fl.Param(), fl.Field()) },
			tv.AlwaysValidate(),
		)

		return err
	})
}

func WithErrorTranslator(et ErrorTranslator) Option {
	return optionFunc(func(v *validator.Validate, t ut.Translator) error {
		registerFn := func(ut ut.Translator) error {
			return ut.Add(et.Tag(), et.MessageTemplate(), true)
		}

		return v.RegisterTranslation(et.Tag(), t, registerFn,
			func(ut ut.Translator, fe validator.FieldError) string {
				translation, err := ut.T(et.Tag(), fe.Field(), et.ErrorMessage(fe.Param()))
				if err != nil {
					return fe.Error()
				}

				return translation
			},
		)
	})
}

func WithTagNameSupplier(tns TagNameSupplier) Option {
	return optionFunc(func(v *validator.Validate, _ ut.Translator) error {
		v.RegisterTagNameFunc(tns.TagName)

		return nil
	})
}
