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

package cellib

import (
	"fmt"
	"maps"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
)

//nolint:gochecknoglobals
var (
	subjectType   = cel.ObjectType(reflect.TypeFor[CelSubject]().String(), traits.ReceiverType|traits.IndexerType)
	principalType = cel.ObjectType(reflect.TypeFor[celPrincipal]().String(), traits.ReceiverType|traits.IndexerType)
)

type CelSubject identity.Subject

func WrapSubject(sub identity.Subject) CelSubject {
	return CelSubject(sub)
}

func (c CelSubject) Type() ref.Type {
	return subjectType
}

func (c CelSubject) Value() any {
	return identity.Subject(c)
}

func (c CelSubject) Equal(other ref.Val) ref.Val {
	if otherSub, ok := other.(CelSubject); ok {
		return types.Bool(maps.EqualFunc(c, otherSub,
			func(first *identity.Principal, second *identity.Principal) bool {
				return first.ID == second.ID && reflect.DeepEqual(first.Attributes, second.Attributes)
			},
		))
	}

	return types.False
}

func (c CelSubject) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeFor[identity.Subject]().AssignableTo(typeDesc) {
		return identity.Subject(c), nil
	}

	if reflect.TypeFor[CelSubject]().AssignableTo(typeDesc) {
		return c, nil
	}

	return nil, fmt.Errorf("%w: from 'Subject' to '%v'", errTypeConversion, typeDesc)
}

func (c CelSubject) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case subjectType:
		return c
	case cel.TypeType:
		return subjectType
	}

	return types.NewErr("type conversion error from 'Subject' to '%s'", typeVal)
}

func (c CelSubject) Get(key ref.Val) ref.Val {
	// CEL engine ensures it is a string
	// nolint: forcetypeassert
	fieldName := key.Value().(string)

	switch fieldName {
	case "ID":
		return types.String(identity.Subject(c).ID())
	case "Attributes":
		return types.NewStringInterfaceMap(types.DefaultTypeAdapter, identity.Subject(c).Attributes())
	default:
		if p, ok := identity.Subject(c)[fieldName]; ok {
			return celPrincipal{principal: p}
		}

		return types.NewErr("unknown field: %s", fieldName)
	}
}

type celPrincipal struct {
	principal *identity.Principal
}

func (c celPrincipal) Type() ref.Type {
	return principalType
}

func (c celPrincipal) Value() any {
	return c.principal
}

func (c celPrincipal) Equal(other ref.Val) ref.Val {
	if otherP, ok := other.(celPrincipal); ok {
		return types.Bool(c.principal.ID == otherP.principal.ID &&
			reflect.DeepEqual(c.principal.Attributes, otherP.principal.Attributes))
	}

	return types.False
}

func (c celPrincipal) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeFor[*identity.Principal]().AssignableTo(typeDesc) {
		return c.principal, nil
	}

	if reflect.TypeFor[celPrincipal]().AssignableTo(typeDesc) {
		return c, nil
	}

	return nil, fmt.Errorf("%w: from 'Principal' to '%v'", errTypeConversion, typeDesc)
}

func (c celPrincipal) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case principalType:
		return c
	case cel.TypeType:
		return principalType
	}

	return types.NewErr("type conversion error from 'Principal' to '%s'", typeVal)
}

func (c celPrincipal) Get(key ref.Val) ref.Val {
	// CEL engine ensures it is a string
	// nolint: forcetypeassert
	fieldName := key.Value().(string)

	switch fieldName {
	case "ID":
		return types.String(c.principal.ID)
	case "Attributes":
		return types.NewStringInterfaceMap(types.DefaultTypeAdapter, c.principal.Attributes)
	default:
		// attributes nested access: principal.Attributes.foo
		// if you want to allow Subject.foo.bar (not typical), handle here
		return types.NewErr("unknown field: %s", fieldName)
	}
}

func Subjects() cel.EnvOption {
	return cel.Lib(subjectLib{})
}

type subjectLib struct{}

func (subjectLib) LibraryName() string { return "dadrus.heimdall.subjects" }

func (subjectLib) ProgramOptions() []cel.ProgramOption { return []cel.ProgramOption{} }

func (subjectLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("Subject", cel.DynType),
	}
}
