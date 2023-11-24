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
var (
	errType    = cel.ObjectType(reflect.TypeOf(Error{}).String(), traits.ComparerType)
	errTypeDef = cel.ObjectType(reflect.TypeOf(ErrorType{}).String(), traits.ComparerType)
)

type ErrorType struct {
	types []error

	current error
}

func (e ErrorType) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, fmt.Errorf("%w: 'ErrorType' cannot be converted to any native type", errTypeConversion)
}

func (e ErrorType) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case errTypeDef:
		return e
	case cel.TypeType:
		return errTypeDef
	}

	return types.NewErr("type conversion error from 'ErrorType' to '%s'", typeVal)
}

func (e ErrorType) Equal(other ref.Val) ref.Val {
	otherEt, ok := other.(ErrorType)
	if !ok {
		return types.False
	}

	if len(e.types) != 0 && len(otherEt.types) != 0 {
		return types.Bool(slices.Equal(e.types, otherEt.types))
	}

	cur := x.IfThenElse(e.current != nil, e.current, otherEt.current)
	errTypes := x.IfThenElse(len(e.types) != 0, e.types, otherEt.types)

	for _, v := range errTypes {
		if errors.Is(cur, v) {
			return types.True
		}
	}

	return types.False
}

func (e ErrorType) Type() ref.Type {
	return errType
}

func (e ErrorType) Value() any {
	return e
}

type Error struct {
	errType ErrorType

	Source string
}

func (e Error) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(e.errType.current).AssignableTo(typeDesc) {
		return e.errType.current, nil
	}

	return nil, fmt.Errorf("%w: from 'Error' to '%v'", errTypeConversion, typeDesc)
}

func (e Error) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case errType:
		return e
	case cel.TypeType:
		return e.errType
	}

	return types.NewErr("type conversion error from 'Error' to '%s'", typeVal)
}

func (e Error) Equal(other ref.Val) ref.Val {
	if otherErr, ok := other.(Error); ok {
		return types.Bool(e.errType.current == otherErr.errType.current)
	}

	return types.False
}

func (e Error) Type() ref.Type {
	return errType
}

func (e Error) Value() any {
	return e
}

func WrapError(err error) Error {
	var (
		handlerIdentifier interface{ ID() string }
		source            string
	)

	if ok := errors.As(err, &handlerIdentifier); ok {
		source = handlerIdentifier.ID()
	} else {
		source = ""
	}

	return Error{errType: ErrorType{current: err}, Source: source}
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

		cel.Constant("authentication_error", cel.DynType,
			ErrorType{types: []error{heimdall.ErrAuthentication}}),
		cel.Constant("authorization_error", cel.DynType,
			ErrorType{types: []error{heimdall.ErrAuthorization}}),
		cel.Constant("communication_error", cel.DynType,
			ErrorType{types: []error{heimdall.ErrCommunication, heimdall.ErrCommunicationTimeout}}),
		cel.Constant("internal_error", cel.DynType,
			ErrorType{types: []error{heimdall.ErrInternal, heimdall.ErrConfiguration}}),
		cel.Constant("precondition_error", cel.DynType,
			ErrorType{types: []error{heimdall.ErrArgument}}),
	}
}
