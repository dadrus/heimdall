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
			reflect.TypeOf(SimpleURL{})),
		cel.Variable("Request", cel.ObjectType("cellib.Request")),
		cel.Variable("Subject", cel.DynType),
		cel.Function("Header", cel.MemberOverload("Header",
			[]*cel.Type{cel.ObjectType("cellib.Request"), cel.StringType}, cel.StringType)),
		cel.Function("Cookie", cel.MemberOverload("Cookie",
			[]*cel.Type{cel.ObjectType("cellib.Request"), cel.StringType}, cel.StringType)),
		cel.Function("ClientIPs", cel.MemberOverload("ClientIPs",
			[]*cel.Type{cel.ObjectType("cellib.Request")}, cel.ListType(cel.StringType))),
	}
}

func (heimdallLibrary) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func Library() cel.EnvOption {
	return cel.Lib(heimdallLibrary{})
}
