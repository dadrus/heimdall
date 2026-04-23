// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package errorhandlers

import (
	"errors"
	"reflect"

	"github.com/go-viper/mapstructure/v2"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var errInvalidHeaderConfiguration = errors.New("invalid header configuration")

func DecodeHeaderEntryHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var entry HeaderEntry

		if from.Kind() != reflect.Map {
			return data, nil
		}

		dect := reflect.ValueOf(&entry).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		typed, err := decodeHeaderEntryMap(data)
		if err != nil {
			return nil, err
		}

		if len(typed) != 1 {
			return nil, errorchain.NewWithMessage(errInvalidHeaderConfiguration,
				"expected exactly one name/value pair")
		}

		for name, rawValue := range typed {
			value, ok := rawValue.(string)
			if !ok {
				return nil, errorchain.NewWithMessagef(errInvalidHeaderConfiguration,
					"header '%s' value is not a string", name)
			}

			if len(value) == 0 || len(name) == 0 {
				continue
			}

			tpl, err := template.New(value)
			if err != nil {
				return nil, errorchain.NewWithMessagef(errInvalidHeaderConfiguration,
					"failed parsing value for header '%s'", name).
					CausedBy(err)
			}

			return HeaderEntry{Name: name, Value: tpl}, nil
		}

		return nil, errorchain.NewWithMessage(errInvalidHeaderConfiguration,
			"neither name nor value can be empty")
	}
}

func decodeHeaderEntryMap(in any) (map[string]any, error) {
	rv := reflect.ValueOf(in)

	result := make(map[string]any, rv.Len())
	for _, key := range rv.MapKeys() {
		if key.Kind() != reflect.String {
			return nil, errorchain.NewWithMessage(errInvalidHeaderConfiguration,
				"header name must be a string")
		}

		result[key.String()] = rv.MapIndex(key).Interface()
	}

	return result, nil
}
