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

	if err := registerTranslations(validate, translate); err != nil {
		panic(err)
	}

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		return "'" + strings.SplitN(fld.Tag.Get("mapstructure"), ",", 2)[0] + "'" // nolint: gomnd
	})
}

func ValidateStruct(s any) error { return wrapError(validate.Struct(s), translate) }
