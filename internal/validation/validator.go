package validation

import (
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	entranslations "github.com/go-playground/validator/v10/translations/en"
)

var DefaultValidator *Validator

func init() {
	var err error

	if DefaultValidator, err = NewValidator(); err != nil {
		panic(err)
	}
}

type Validator struct {
	v *validator.Validate
	t ut.Translator
}

func (v *Validator) ValidateStruct(s any) error { return wrapError(v.v.Struct(s), v.t) }

func NewValidator(opts ...Option) (*Validator, error) {
	enLoc := en.New()
	uni := ut.New(enLoc, enLoc)
	translate, _ := uni.GetTranslator("en")
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := entranslations.RegisterDefaultTranslations(validate, translate); err != nil {
		return nil, err
	}

	if err := registerTranslations(validate, translate); err != nil {
		return nil, err
	}

	getTagValue := func(tag reflect.StructTag) string {
		for _, tagName := range []string{"mapstructure", "json", "yaml", "koanf"} {
			val := tag.Get(tagName)
			if len(val) != 0 {
				return val
			}
		}

		return ""
	}

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := getTagValue(fld.Tag)
		if len(name) == 0 {
			name = fld.Name
		}

		return "'" + strings.SplitN(name, ",", 2)[0] + "'" // nolint: mnd
	})

	for _, opt := range opts {
		if err := opt.apply(validate, translate); err != nil {
			return nil, err
		}
	}

	return &Validator{
		v: validate,
		t: translate,
	}, nil
}

func ValidateStruct(s any) error { return DefaultValidator.ValidateStruct(s) }
