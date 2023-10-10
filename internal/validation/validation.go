package validation

import (
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	entranslations "github.com/go-playground/validator/v10/translations/en"
)

var (
	validate  *validator.Validate //nolint:gochecknoglobals
	translate ut.Translator       //nolint:gochecknoglobals
)

//nolint:gochecknoinits
func init() {
	enLoc := en.New()
	uni := ut.New(enLoc, enLoc)
	translate, _ = uni.GetTranslator("en")
	validate = validator.New(validator.WithRequiredStructEnabled())

	if err := entranslations.RegisterDefaultTranslations(validate, translate); err != nil {
		panic(err)
	}

	if err := validate.RegisterTranslation(
		"required_without",
		translate,
		func(ut ut.Translator) error {
			return ut.Add(
				"required_without",
				"{0} is a required field as long as {1} is not set",
				false,
			)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			translation, err := ut.T(fe.Tag(), fe.Field(), strings.ToLower(fe.Param()))
			if err != nil {
				return fe.Error()
			}

			return translation
		},
	); err != nil {
		panic(err)
	}

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		return "'" + strings.SplitN(fld.Tag.Get("mapstructure"), ",", 2)[0] + "'" // nolint: gomnd
	})
}

func ValidateStruct(s any) error { return wrapError(validate.Struct(s), translate) }
