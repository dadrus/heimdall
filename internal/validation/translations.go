package validation

import (
	"strings"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

func registerTranslations(validate *validator.Validate, trans ut.Translator) error {
	translations := []struct {
		tag             string
		translation     string
		override        bool
		customRegisFunc validator.RegisterTranslationsFunc
		customTransFunc validator.TranslationFunc
	}{
		{
			tag:         "required_without",
			translation: "{0} is a required field as long as {1} is not set",
			override:    false,
			customTransFunc: func(ut ut.Translator, fe validator.FieldError) string {
				translation, err := ut.T(fe.Tag(), fe.Field(), strings.ToLower(fe.Param()))
				if err != nil {
					return fe.Error()
				}

				return translation
			},
		},
		{
			tag:         "gt",
			translation: "{0} must be greater then {1}",
			override:    false,
			customTransFunc: func(ut ut.Translator, fe validator.FieldError) string {
				translation, err := ut.T(fe.Tag(), fe.Field(), fe.Param())
				if err != nil {
					return fe.Error()
				}

				return translation
			},
		},
	}

	for _, entry := range translations {
		var err error

		switch {
		case entry.customTransFunc != nil && entry.customRegisFunc != nil:
			err = validate.RegisterTranslation(entry.tag, trans, entry.customRegisFunc, entry.customTransFunc)
		case entry.customTransFunc != nil && entry.customRegisFunc == nil:
			err = validate.RegisterTranslation(entry.tag, trans,
				registrationFunc(entry.tag, entry.translation, entry.override), entry.customTransFunc)
		case entry.customTransFunc == nil && entry.customRegisFunc != nil:
			err = validate.RegisterTranslation(entry.tag, trans, entry.customRegisFunc, translateFunc)
		default:
			err = validate.RegisterTranslation(entry.tag, trans,
				registrationFunc(entry.tag, entry.translation, entry.override), translateFunc)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func registrationFunc(tag string, translation string, override bool) validator.RegisterTranslationsFunc {
	return func(ut ut.Translator) error {
		return ut.Add(tag, translation, override)
	}
}

func translateFunc(ut ut.Translator, fe validator.FieldError) string {
	t, err := ut.T(fe.Tag(), fe.Field())
	if err != nil {
		return fe.Error()
	}

	return t
}
