package cellib

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type heimdallLibrary struct{}

func (heimdallLibrary) LibraryName() string {
	return "dadrus.heimdall"
}

func (heimdallLibrary) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.DefaultUTCTimeZone(true),
		ext.NativeTypes(
			reflect.TypeOf(&subject.Subject{}),
			reflect.TypeOf(&Request{}),
			reflect.TypeOf(&URL{})),
		cel.Variable("Payload", cel.DynType),
		cel.Variable("Subject", cel.DynType),
		cel.Variable("Request", cel.ObjectType(requestType.TypeName())),
		cel.Function("Header", cel.MemberOverload("Header",
			[]*cel.Type{cel.ObjectType("cellib.Request"), cel.StringType}, cel.StringType)),
		cel.Function("Cookie", cel.MemberOverload("Cookie",
			[]*cel.Type{cel.ObjectType("cellib.Request"), cel.StringType}, cel.StringType)),
		cel.Function("String", cel.MemberOverload("String",
			[]*cel.Type{cel.ObjectType("cellib.URL")}, cel.StringType)),
		cel.Function("Query", cel.MemberOverload("Query",
			[]*cel.Type{cel.ObjectType("cellib.URL")}, cel.DynType)),
	}
}

func (heimdallLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func Library() cel.EnvOption {
	return cel.Lib(heimdallLibrary{})
}
