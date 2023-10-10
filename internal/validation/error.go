package validation

import (
	"errors"
	"strings"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
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
		translations := errs.Translate(v.t)
		messages := make([]string, len(translations))
		idx := 0

		for key, value := range errs.Translate(v.t) {
			ns := strings.Split(key, ".")
			namespace := strings.Join(ns[1:len(ns)-1], ".")

			if len(namespace) == 0 {
				messages[idx] = value
			} else {
				messages[idx] = namespace + "." + value
			}

			idx++
		}

		return strings.Join(messages, ", ")
	}

	return v.err.Error()
}
