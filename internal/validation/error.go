package validation

import (
	"errors"
	"strings"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	"golang.org/x/exp/maps"
)

func wrapError(err error, trans ut.Translator) error {
	if err == nil {
		return nil
	}

	return &validationError{err: err, t: trans}
}

type validationError struct {
	err error
	t   ut.Translator
}

func (v *validationError) Error() string {
	var errs validator.ValidationErrors
	if errors.As(v.err, &errs) {
		return strings.Join(maps.Values(errs.Translate(v.t)), ", ")
	}

	return v.err.Error()
}
