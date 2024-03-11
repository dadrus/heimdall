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

package redis

import (
	"reflect"
)

func decodeCredentialsHookFunc(from reflect.Type, to reflect.Type, data any) (any, error) {
	var cred credentials

	if from.Kind() != reflect.Map {
		return data, nil
	}

	dect := reflect.ValueOf(&cred).Elem().Type()
	if !dect.AssignableTo(to) {
		return data, nil
	}

	vals := data.(map[string]any) // nolint: forcetypeassert

	if un, ok := vals["path"]; ok {
		creds := &fileCredentials{Path: un.(string)} // nolint: forcetypeassert
		if err := creds.load(); err != nil {
			return nil, err
		}

		return creds, nil
	}

	var (
		username string
		password string
	)

	if un, ok := vals["username"]; ok {
		username = un.(string) // nolint: forcetypeassert
	}

	if pass, ok := vals["password"]; ok {
		password = pass.(string) // nolint: forcetypeassert
	}

	return &staticCredentials{Username: username, Password: password}, nil

}
