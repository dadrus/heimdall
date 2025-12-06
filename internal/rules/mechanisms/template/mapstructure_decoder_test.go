// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package template

import (
	"io"
	"reflect"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/require"
)

func TestDecodeTemplateHookFunc(t *testing.T) {
	t.Parallel()

	hookFunc := DecodeTemplateHookFunc()

	tplValue := reflect.Zero(reflect.TypeFor[Template]())
	someValue := reflect.Zero(reflect.TypeFor[io.Reader]())

	for uc, tc := range map[string]struct {
		from, to reflect.Value
		decoded  bool
	}{
		"assignable string without template usage": {reflect.ValueOf("some string"), tplValue, true},
		"integer value":                   {reflect.ValueOf(42), tplValue, false},
		"assignable empty string":         {reflect.ValueOf(""), tplValue, true},
		"assignable string with template": {reflect.ValueOf("{{ .Foo }}"), tplValue, true},
		"not assignable string":           {reflect.ValueOf("some string"), someValue, false},
	} {
		t.Run(uc, func(t *testing.T) {
			res, err := mapstructure.DecodeHookExec(hookFunc, tc.from, tc.to)

			require.NoError(t, err)
			require.NotNil(t, res)

			if tc.decoded {
				require.IsType(t, &templateImpl{}, res)
			}
		})
	}
}
