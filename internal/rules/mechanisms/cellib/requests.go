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

func Requests() cel.EnvOption {
	return cel.Lib(requestsLib{})
}

type requestsLib struct{}

func (requestsLib) LibraryName() string {
	return "dadrus.heimdall.requests"
}

func (requestsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (requestsLib) CompileOptions() []cel.EnvOption {
	requestType := cel.ObjectType(reflect.TypeOf(heimdall.Request{}).String(), traits.ReceiverType)

	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(&heimdall.Request{})),
		cel.Function("Header",
			cel.MemberOverload("request_Header",
				[]*cel.Type{requestType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := lhs.Value().(*heimdall.Request)

					// nolint: forcetypeassert
					return types.String(req.Header(rhs.Value().(string)))
				}),
			),
		),
		cel.Function("Cookie",
			cel.MemberOverload("request_Cookie",
				[]*cel.Type{requestType, cel.StringType}, cel.StringType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					// nolint: forcetypeassert
					req := lhs.Value().(*heimdall.Request)

					// nolint: forcetypeassert
					return types.String(req.Cookie(rhs.Value().(string)))
				}),
			),
		),
	}
}
