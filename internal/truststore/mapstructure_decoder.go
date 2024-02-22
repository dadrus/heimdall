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

package truststore

import (
	"reflect"

	"github.com/go-viper/mapstructure/v2"
)

func DecodeTrustStoreHookFunc() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		var trustStore TrustStore

		if from.Kind() != reflect.String {
			return data, nil
		}

		dect := reflect.ValueOf(&trustStore).Elem().Type()
		if !dect.AssignableTo(to) {
			return data, nil
		}

		// nolint: forcetypeassert
		// already checked above
		return NewTrustStoreFromPEMFile(data.(string), true)
	}
}
