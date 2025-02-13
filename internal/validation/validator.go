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
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	entranslations "github.com/go-playground/validator/v10/translations/en"
)

type Validator interface {
	ValidateStruct(s any) error
}

type validatorImpl struct {
	v *validator.Validate
	t ut.Translator
}

func (v *validatorImpl) ValidateStruct(s any) error { return wrapError(v.v.Struct(s), v.t) }

func NewValidator(opts ...Option) (Validator, error) {
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

	return &validatorImpl{
		v: validate,
		t: translate,
	}, nil
}
