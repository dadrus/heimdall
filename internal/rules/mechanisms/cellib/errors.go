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

//nolint:gochecknoglobals
var (
	errType     = cel.ObjectType(reflect.TypeOf(Error{}).String(), traits.ComparerType)
	errTypeType = cel.ObjectType(reflect.TypeOf(Error{}).String(), traits.ComparerType)
)

type ErrorType struct {
	types []error
}

func (e ErrorType) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, fmt.Errorf("%w: 'ErrorType' cannot be converted to any native type", errTypeConversion)
}

func (e ErrorType) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case errTypeType:
		return e
	case cel.TypeType:
		return errTypeType
	}

	return types.NewErr("type conversion error from 'ErrorType' to '%s'", typeVal)
}

func (e ErrorType) Equal(other ref.Val) ref.Val {
	if otherEt, ok := other.(ErrorType); ok {
		return types.Bool(slices.Equal(e.types, otherEt.types))
	}

	if otherErr, ok := other.(Error); ok {
		for _, v := range e.types {
			if errors.Is(otherErr.err, v) {
				return types.True
			}
		}
	}

	return types.False
}

func (e ErrorType) Type() ref.Type { return errType }

func (e ErrorType) Value() any { return e }

type Error struct {
	err error

	Source string
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
	if otherEt, ok := other.(ErrorType); ok {
		return otherEt.Equal(e)
	}

	if otherErr, ok := other.(Error); ok {
		return types.Bool(errors.Is(e.err, otherErr.err))
	}

	return types.False
}

func (e Error) Type() ref.Type { return errType }

func (e Error) Value() any { return e }

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

	return Error{err: err, Source: source}
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
			ErrorType{types: []error{heimdall.ErrAuthentication}}),
		cel.Constant("authorization_error", errType,
			ErrorType{types: []error{heimdall.ErrAuthorization}}),
		cel.Constant("communication_error", errType,
			ErrorType{types: []error{heimdall.ErrCommunication, heimdall.ErrCommunicationTimeout}}),
		cel.Constant("internal_error", errType,
			ErrorType{types: []error{heimdall.ErrInternal, heimdall.ErrConfiguration}}),
		cel.Constant("precondition_error", errType,
			ErrorType{types: []error{heimdall.ErrArgument}}),
	}
}
