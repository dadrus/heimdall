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

package cellib

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
)

func Urls() cel.EnvOption {
	return cel.Lib(urlsLib{})
}

type urlsLib struct{}

func (urlsLib) LibraryName() string {
	return "dadrus.heimdall.urls"
}

func (urlsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (urlsLib) CompileOptions() []cel.EnvOption {
	urlType := cel.ObjectType(reflect.TypeOf(heimdall.URL{}).String(), traits.ReceiverType)

	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(&heimdall.URL{})),
		cel.Function("String",
			cel.MemberOverload("url_String",
				[]*cel.Type{urlType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.String(value.Value().(*heimdall.URL).String())
				}),
			),
		),
		cel.Function("Query",
			cel.MemberOverload("url_Query",
				[]*cel.Type{urlType}, cel.MapType(types.StringType, cel.ListType(cel.StringType)),
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.NewDynamicMap(types.DefaultTypeAdapter, value.Value().(*heimdall.URL).Query())
				}),
			),
		),
		cel.Function("Hostname",
			cel.MemberOverload("url_Hostname",
				[]*cel.Type{urlType}, types.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.String(value.Value().(*heimdall.URL).Hostname())
				}),
			),
		),
		cel.Function("Port",
			cel.MemberOverload("url_Port",
				[]*cel.Type{urlType}, types.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.String(value.Value().(*heimdall.URL).Port())
				}),
			),
		),
	}
}
