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
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

type heimdallLibrary struct{}

func (heimdallLibrary) LibraryName() string {
	return "dadrus.heimdall.main"
}

func (heimdallLibrary) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.DefaultUTCTimeZone(true),
		cel.StdLib(),
		ext.Lists(),
		ext.Encoders(),
		ext.Math(),
		ext.Sets(),
		ext.Strings(),
		Lists(),
		Strings(),
		Urls(),
		Requests(),
		Errors(),
		Networks(),
		ext.NativeTypes(reflect.TypeOf(&subject.Subject{})),
		cel.Variable("Payload", cel.DynType),
		cel.Variable("Subject", cel.DynType),
		cel.Variable("Request", cel.DynType),
	}
}

func (heimdallLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func Library() cel.EnvOption {
	return cel.Lib(heimdallLibrary{})
}
