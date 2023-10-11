package validation

import (
	"errors"
	"strings"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"

	"github.com/dadrus/heimdall/internal/x/slicex"
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

		for key, value := range translations {
			ns := strings.Split(key, ".")
			ns = slicex.Filter(ns[1:len(ns)-1], func(s string) bool {
				return len(strings.Trim(s, "'")) != 0
			})
			namespace := strings.Join(ns, ".")

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
