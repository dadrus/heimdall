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

		return "validation error: " + strings.Join(messages, ", ")
	}

	return v.err.Error()
}
