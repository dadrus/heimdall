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
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

func Lists() cel.EnvOption {
	return cel.Lib(listsLib{})
}

type listsLib struct{}

func (listsLib) LibraryName() string {
	return "dadrus.heimdall.lists"
}

func (listsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (listsLib) CompileOptions() []cel.EnvOption {
	listType := cel.ListType(cel.TypeParamType("T"))

	return []cel.EnvOption{
		cel.Function("last",
			cel.MemberOverload("list_last",
				[]*cel.Type{listType}, cel.TypeParamType("T"),
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					return last(value.(traits.Lister)) // nolint: forcetypeassert
				}),
			),
		),
		cel.Function("at",
			cel.MemberOverload("list_at",
				[]*cel.Type{listType, cel.IntType}, cel.TypeParamType("T"),
				cel.BinaryBinding(func(listVal ref.Val, valPos ref.Val) ref.Val {
					result, err := at(listVal.(traits.Lister), valPos.(types.Int)) // nolint: forcetypeassert
					if err != nil {
						return types.WrapErr(err)
					}

					return result
				}),
			),
		),
	}
}

func last(list traits.Lister) ref.Val {
	listLength := list.Size().(types.Int) // nolint: forcetypeassert

	if listLength == 0 {
		return nil
	}

	return types.DefaultTypeAdapter.NativeToValue(list.Get(listLength - 1))
}

func at(listVal traits.Lister, pos types.Int) (ref.Val, error) {
	list := listVal
	listLength := listVal.Size().(types.Int) // nolint: forcetypeassert

	if pos >= 0 && pos >= listLength {
		// nolint: goerr113
		return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
	}

	if pos < 0 && (-pos-1) >= listLength {
		// nolint: goerr113
		return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
	}

	if pos >= 0 {
		return types.DefaultTypeAdapter.NativeToValue(list.Get(pos)), nil
	}

	return types.DefaultTypeAdapter.NativeToValue(list.Get(listLength + pos)), nil
}
