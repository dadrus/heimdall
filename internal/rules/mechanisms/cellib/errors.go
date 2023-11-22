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
)

var errTypeType = cel.ObjectType(reflect.TypeOf(ErrorType{}).String(), traits.ReceiverType)

type ErrorType []error

func (et ErrorType) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(et).AssignableTo(typeDesc) {
		return et, nil
	}

	if reflect.TypeOf([]error(et)).AssignableTo(typeDesc) {
		return []error(et), nil
	}

	return nil, fmt.Errorf("%w: from 'ErrorType' to '%v'", errTypeConversion, typeDesc)
}

func (et ErrorType) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case errTypeType:
		return et
	case cel.TypeType:
		return errTypeType
	}

	return types.NewErr("type conversion error from 'networks' to '%s'", typeVal)
}

func (et ErrorType) Equal(other ref.Val) ref.Val {
	otherEt, ok := other.(ErrorType)

	return types.Bool(ok && slices.Equal(et, otherEt))
}

func (et ErrorType) Type() ref.Type {
	return errTypeType
}

func (et ErrorType) Value() any {
	return et
}

type Error struct {
	err error
}

func (e Error) is(et ErrorType) bool {
	for _, v := range et {
		if errors.Is(e.err, v) {
			return true
		}
	}

	return false
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
	errType := cel.ObjectType(reflect.TypeOf(Error{}).String(), traits.ReceiverType|traits.ComparerType)

	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(Error{})),
		cel.Variable("Error", errType),

		cel.Constant("authentication_error", errTypeType, ErrorType{heimdall.ErrAuthentication}),
		cel.Constant("authorization_error", errTypeType, ErrorType{heimdall.ErrAuthorization}),
		cel.Constant("internal_error", errTypeType, ErrorType{heimdall.ErrInternal, heimdall.ErrConfiguration}),
		cel.Constant("precondition_error", errTypeType, ErrorType{heimdall.ErrArgument}),

		cel.Function("Source",
			cel.MemberOverload("error_Source",
				[]*cel.Type{errType}, cel.StringType,
				cel.UnaryBinding(func(errVal ref.Val) ref.Val {
					err := errVal.Value().(Error) // nolint: forcetypeassert

					return types.String(err.source())
				}),
			),
		),
		cel.Function("Is",
			cel.MemberOverload("error_Is",
				[]*cel.Type{errType, errTypeType}, cel.BoolType,
				cel.BinaryBinding(func(errVal ref.Val, typeVal ref.Val) ref.Val {
					err := errVal.Value().(Error)            // nolint: forcetypeassert
					errorType := typeVal.Value().(ErrorType) // nolint: forcetypeassert

					return types.Bool(err.is(errorType))
				}),
			),
		),
	}
}
