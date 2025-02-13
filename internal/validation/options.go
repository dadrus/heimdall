// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
