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

func Results() cel.EnvOption {
	return cel.Lib(resultsLib{})
}

type resultsLib struct{}

func (resultsLib) LibraryName() string {
	return "dadrus.heimdall.results"
}

func (resultsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (resultsLib) CompileOptions() []cel.EnvOption {
	resultType := cel.ObjectType(
		reflect.TypeOf(heimdall.Result{}).String(),
		traits.ReceiverType,
	)

	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(&heimdall.Result{})),
		cel.Function(
			"Header",
			cel.MemberOverload(
				"result_Header",
				[]*cel.Type{resultType, cel.StringType},
				cel.StringType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					//nolint:forcetypeassert
					result := lhs.Value().(*heimdall.Result)

					//nolint:forcetypeassert
					return types.String(result.Header(rhs.Value().(string)))
				}),
			),
		),
	}
}
