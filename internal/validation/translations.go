// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"strconv"
	"strings"
	"time"

	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

//nolint:cyclop,funlen,gocognit
func registerTranslations(validate *validator.Validate, trans ut.Translator) error {
	translations := []struct {
		tag             string
		translation     string
		override        bool
		customRegisFunc validator.RegisterTranslationsFunc
		customTransFunc validator.TranslationFunc
	}{
		{
			tag: "gt",
			customRegisFunc: func(ut ut.Translator) error {
				return ut.Add("gt-duration", "{0} must be greater than {1}", false)
			},
			customTransFunc: func(ut ut.Translator, fe validator.FieldError) string {
				var err error
				var translation string
				var f64 float64
				var digits uint64
				var kind reflect.Kind

				fn := func() {
					if idx := strings.Index(fe.Param(), "."); idx != -1 {
						digits = uint64(len(fe.Param()[idx+1:]))
					}

					f64, err = strconv.ParseFloat(fe.Param(), 64)
				}

				kind = fe.Kind()
				if kind == reflect.Ptr {
					kind = fe.Type().Elem().Kind()
				}

				switch kind {
				case reflect.String:
					var ct string

					fn()
					if err != nil {
						goto END
					}

					ct, err = ut.C("gt-string-character", f64, digits, ut.FmtNumber(f64, digits))
					if err != nil {
						goto END
					}

					translation, err = ut.T("gt-string", fe.Field(), ct)

				case reflect.Slice, reflect.Map, reflect.Array:
					var ct string

					fn()
					if err != nil {
						goto END
					}

					ct, err = ut.C("gt-items-item", f64, digits, ut.FmtNumber(f64, digits))
					if err != nil {
						goto END
					}

					translation, err = ut.T("gt-items", fe.Field(), ct)

				case reflect.Struct:
					if fe.Type() != reflect.TypeOf(time.Time{}) {
						goto END
					}

					translation, err = ut.T("gt-datetime", fe.Field())
				case reflect.Int64:
					if fe.Type() == reflect.TypeOf(time.Duration(0)) {
						translation, err = ut.T("gt-duration", fe.Field(), fe.Param())

						goto END
					}

					fallthrough
				default:
					fn()
					if err != nil {
						goto END
					}

					translation, err = ut.T("gt-number", fe.Field(), ut.FmtNumber(f64, digits))
				}

			END:
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
