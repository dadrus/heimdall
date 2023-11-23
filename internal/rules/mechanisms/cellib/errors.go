package cellib

import (
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x"
)

//nolint:gochecknoglobals
var errType = cel.ObjectType(reflect.TypeOf(Error{}).String(), traits.ReceiverType|traits.ComparerType)

type Error struct {
	types []error
	err   error
}

func (e Error) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(e.err).AssignableTo(typeDesc) {
		return e.err, nil
	}

	return nil, fmt.Errorf("%w: from 'Error' to '%v'", errTypeConversion, typeDesc)
}

func (e Error) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case errType:
		return e
	case cel.TypeType:
		return errType
	}

	return types.NewErr("type conversion error from 'Error' to '%s'", typeVal)
}

func (e Error) Equal(other ref.Val) ref.Val {
	otherEt, ok := other.(Error)

	if len(e.types) != 0 && len(otherEt.types) != 0 {
		return types.Bool(ok && slices.Equal(e.types, otherEt.types))
	}

	errTypes := x.IfThenElse(len(e.types) != 0, e.types, otherEt.types)
	err := x.IfThenElse(e.err != nil, e.err, otherEt.err)

	for _, v := range errTypes {
		if errors.Is(err, v) {
			return types.True
		}
	}

	return types.False
}

func (e Error) Type() ref.Type {
	return errType
}

func (e Error) Value() any {
	return e
}

func (e Error) source() string {
	var handlerIdentifier interface{ ID() string }

	if ok := errors.As(e.err, &handlerIdentifier); ok {
		return handlerIdentifier.ID()
	}

	return ""
}

func WrapError(err error) Error {
	return Error{err: err}
}

func Errors() cel.EnvOption {
	return cel.Lib(errorsLib{})
}

type errorsLib struct{}

func (errorsLib) LibraryName() string {
	return "dadrus.heimdall.errors"
}

func (errorsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (errorsLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(Error{})),
		cel.Variable("Error", errType),

		cel.Constant("authentication_error", errType,
			Error{types: []error{heimdall.ErrAuthentication}}),
		cel.Constant("authorization_error", errType,
			Error{types: []error{heimdall.ErrAuthorization}}),
		cel.Constant("internal_error", errType,
			Error{types: []error{heimdall.ErrInternal, heimdall.ErrConfiguration}}),
		cel.Constant("precondition_error", errType,
			Error{types: []error{heimdall.ErrArgument}}),

		cel.Function("Source",
			cel.MemberOverload("error_Source",
				[]*cel.Type{errType}, cel.StringType,
				cel.UnaryBinding(func(errVal ref.Val) ref.Val {
					err := errVal.Value().(Error) // nolint: forcetypeassert

					return types.String(err.source())
				}),
			),
		),
	}
}
