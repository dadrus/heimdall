package cellib

import (
	"net/url"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
)

func Urls() cel.EnvOption {
	return cel.Lib(urlsLib{})
}

type urlsLib struct{}

func (urlsLib) LibraryName() string {
	return "dadrus.heimdall.urls"
}

func (urlsLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (urlsLib) CompileOptions() []cel.EnvOption {
	urlType := cel.ObjectType(reflect.TypeOf(url.URL{}).String(), traits.ReceiverType)

	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeOf(&url.URL{})),
		cel.Function("String",
			cel.MemberOverload("url_String",
				[]*cel.Type{urlType}, cel.StringType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.String(value.Value().(*url.URL).String())
				}),
			),
		),
		cel.Function("Query",
			cel.MemberOverload("url_Query",
				[]*cel.Type{urlType}, cel.MapType(types.StringType, cel.ListType(cel.StringType)),
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					// nolint: forcetypeassert
					return types.NewDynamicMap(types.DefaultTypeAdapter, value.Value().(*url.URL).Query())
				}),
			),
		),
	}
}
