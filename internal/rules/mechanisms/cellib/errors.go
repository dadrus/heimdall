package cellib

import (
	"errors"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Error struct {
	err error
}

func (e Error) is(errType string) bool {
	var realErrorTypes []error

	switch errType {
	case "authentication_error":
		realErrorTypes = []error{heimdall.ErrAuthentication}
	case "authorization_error":
		realErrorTypes = []error{heimdall.ErrAuthorization}
	case "internal_error":
		realErrorTypes = []error{heimdall.ErrInternal, heimdall.ErrConfiguration}
	case "precondition_error":
		realErrorTypes = []error{heimdall.ErrArgument}
	}

	for _, v := range realErrorTypes {
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
	errType := cel.ObjectType(reflect.TypeOf(Error{}).String(), traits.ReceiverType)

	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(Error{})),
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
				[]*cel.Type{errType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(errVal ref.Val, typeVal ref.Val) ref.Val {
					err := errVal.Value().(Error)         // nolint: forcetypeassert
					errorType := typeVal.Value().(string) // nolint: forcetypeassert

					return types.Bool(err.is(errorType))
				}),
			),
		),
	}
}
