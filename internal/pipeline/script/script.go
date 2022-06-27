package script

import (
	"errors"
	"reflect"

	"github.com/dop251/goja"
	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrScriptExecution = errors.New("script error")

type Script interface {
	Execute(ctx heimdall.Context, sub *subject.Subject) (Result, error)
}

type script struct {
	p *goja.Program
}

type Result interface {
	ToInteger() int64
	String() string
	ToFloat() float64
	ToBoolean() bool
	Export() interface{}
	ExportType() reflect.Type
}

func New(val string) (Script, error) {
	programm, err := goja.Compile("", val, true)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "failed to compile script").
			CausedBy(err)
	}

	return &script{p: programm}, nil
}

func (s *script) Execute(ctx heimdall.Context, sub *subject.Subject) (Result, error) {
	logger := zerolog.Ctx(ctx.AppContext())

	vm := goja.New()

	// the error checks below are ignored by intention as these cannot happen here
	// we can also not test the corresponding occurrence and if these would happen
	// the script execution would result in an error anyway, which basically means
	// failed execution of the handler using it.

	hmdl := vm.NewObject()

	// nolint: errcheck
	hmdl.Set("Subject", sub)

	// nolint: errcheck
	hmdl.Set("RequestMethod", func() string { return ctx.RequestMethod() })

	// nolint: errcheck
	hmdl.Set("RequestURL", func() string { return ctx.RequestURL().String() })

	// nolint: errcheck
	hmdl.Set("RequestClientIPs", func() []string { return ctx.RequestClientIPs() })

	// nolint: errcheck
	hmdl.Set("RequestHeader", func(name string) string { return ctx.RequestHeader(name) })

	// nolint: errcheck
	hmdl.Set("RequestCookie", func(name string) string { return ctx.RequestCookie(name) })

	// nolint: errcheck
	hmdl.Set("RequestQueryParameter", func(name string) string { return ctx.RequestQueryParameter(name) })

	console := vm.NewObject()

	// nolint: errcheck
	console.Set("log", func(val string) { logger.Debug().Msg(val) })

	// nolint: errcheck
	vm.Set("heimdall", hmdl)

	// nolint: errcheck
	vm.Set("console", console)

	val, err := vm.RunProgram(s.p)
	if err != nil {
		return nil, errorchain.New(ErrScriptExecution).CausedBy(err)
	}

	return val, nil
}
