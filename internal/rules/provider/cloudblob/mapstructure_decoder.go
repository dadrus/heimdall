// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package cloudblob

import (
	"net/url"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

func urlDecodeHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var exp *url.URL

		dect := reflect.ValueOf(&exp).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		if from.Kind() != reflect.String {
			return data, nil
		}

		// nolint: forcetypeassert
		return url.Parse(data.(string)) // already checked above
	}
}
