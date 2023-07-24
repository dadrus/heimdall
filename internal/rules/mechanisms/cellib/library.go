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

package cellib

import (
	"net/url"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

var (
	//nolint:gochecknoglobals
	requestType = cel.ObjectType(reflect.TypeOf(heimdall.Request{}).String(), traits.ReceiverType)
	//nolint:gochecknoglobals
	urlType = cel.ObjectType(reflect.TypeOf(url.URL{}).String(), traits.ReceiverType)
)

type heimdallLibrary struct{}

func (heimdallLibrary) LibraryName() string {
	return "dadrus.heimdall"
}

func (heimdallLibrary) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.DefaultUTCTimeZone(true),
		ext.NativeTypes(
			reflect.TypeOf(&subject.Subject{}),
			reflect.TypeOf(&heimdall.Request{}),
			reflect.TypeOf(&url.URL{})),
		cel.Variable("Payload", cel.DynType),
		cel.Variable("Subject", cel.DynType),
		cel.Variable("Request", cel.ObjectType(requestType.TypeName())),
		cel.Function("Header",
			cel.MemberOverload("Header",
				[]*cel.Type{cel.ObjectType(requestType.TypeName()), cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := lhs.Value().(*heimdall.Request)

					// nolint: forcetypeassert
					return types.String(req.Header(rhs.Value().(string)))
				}),
			),
		),
		cel.Function("Cookie",
			cel.MemberOverload("Cookie",
				[]*cel.Type{cel.ObjectType(requestType.TypeName()), cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := lhs.Value().(*heimdall.Request)

					// nolint: forcetypeassert
					return types.String(req.Cookie(rhs.Value().(string)))
				}),
			),
		),
		cel.Function("LastURLPathFragment",
			cel.MemberOverload("LastURLPathFragment",
				[]*cel.Type{cel.ObjectType(requestType.TypeName())}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := value.Value().(*heimdall.Request)

					// nolint: forcetypeassert
					return types.String(req.LastURLPathFragment())
				}),
			),
		),
		cel.Function("String",
			cel.MemberOverload("String",
				[]*cel.Type{cel.ObjectType(urlType.TypeName())}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.String(value.Value().(*url.URL).String())
				}),
			),
		),
		cel.Function("Query",
			cel.MemberOverload("Query",
				[]*cel.Type{cel.ObjectType(urlType.TypeName())}, cel.DynType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.NewDynamicMap(types.DefaultTypeAdapter, value.Value().(*url.URL).Query())
				}),
			),
		),
	}
}

func (heimdallLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func Library() cel.EnvOption {
	return cel.Lib(heimdallLibrary{})
}
