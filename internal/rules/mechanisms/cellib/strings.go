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
	"github.com/dlclark/regexp2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func Strings() cel.EnvOption {
	return cel.Lib(stringsLib{})
}

type stringsLib struct{}

func (stringsLib) LibraryName() string {
	return "dadrus.heimdall.strings"
}

func (stringsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (stringsLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("regexFind",
			cel.MemberOverload("string_regexFind",
				[]*cel.Type{cel.StringType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(stringVal, regexVal ref.Val) ref.Val {
					result, err := regexFind(regexVal.Value().(string), stringVal.Value().(string)) // nolint: forcetypeassert
					if err != nil {
						return types.WrapErr(err)
					}

					return types.String(result)
				}),
			),
		),
		cel.Function("regexFindAll",
			cel.MemberOverload("string_regexFindAll",
				[]*cel.Type{cel.StringType, cel.StringType}, cel.ListType(cel.StringType),
				cel.BinaryBinding(func(stringVal, regexVal ref.Val) ref.Val {
					result, err := regexFindAll(regexVal.Value().(string), stringVal.Value().(string)) // nolint: forcetypeassert
					if err != nil {
						return types.WrapErr(err)
					}

					return types.DefaultTypeAdapter.NativeToValue(result)
				}),
			),
		),
	}
}

func regexFind(regex string, value string) (string, error) {
	reg, err := regexp2.Compile(regex, regexp2.RE2)
	if err != nil {
		return "", err
	}

	match, err := reg.FindStringMatch(value)
	if err != nil {
		return "", err
	}

	return match.String(), nil
}

func regexFindAll(regex string, value string) ([]string, error) {
	re, err := regexp2.Compile(regex, regexp2.RE2)
	if err != nil {
		return nil, err
	}

	var matches []string

	match, err := re.FindStringMatch(value)
	if err != nil {
		return nil, err
	}

	for match != nil {
		matches = append(matches, match.String())

		match, err = re.FindNextMatch(match)
		if err != nil {
			return nil, err
		}
	}

	return matches, nil
}
