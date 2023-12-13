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
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func Requests() cel.EnvOption {
	return cel.Lib(requestsLib{})
}

type requestsLib struct{}

func (requestsLib) LibraryName() string {
	return "dadrus.heimdall.requests"
}

func (requestsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (requestsLib) CompileOptions() []cel.EnvOption {
	requestType := cel.ObjectType(reflect.TypeOf(heimdall.Request{}).String(), traits.ReceiverType)

	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(&heimdall.Request{})),
		cel.Variable("Request", cel.DynType),
		cel.Function("Header",
			cel.MemberOverload("request_Header",
				[]*cel.Type{requestType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := lhs.Value().(*heimdall.Request)

					// nolint: forcetypeassert
					return types.String(req.Header(rhs.Value().(string)))
				}),
			),
		),
		cel.Function("Cookie",
			cel.MemberOverload("request_Cookie",
				[]*cel.Type{requestType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := lhs.Value().(*heimdall.Request)

					// nolint: forcetypeassert
					return types.String(req.Cookie(rhs.Value().(string)))
				}),
			),
		),
		cel.Function("Body",
			cel.MemberOverload("request_Body",
				[]*cel.Type{requestType}, cel.DynType,
				cel.UnaryBinding(func(lhs ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := lhs.Value().(*heimdall.Request)

					return types.DefaultTypeAdapter.NativeToValue(req.Body())
				}),
			),
		),
	}
}
