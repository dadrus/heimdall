package cellib

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	"github.com/dadrus/heimdall/internal/heimdall"
)

var (
	errTypeConversion = errors.New("type conversion error")

	requestType = types.NewTypeValue("Test", traits.ReceiverType) //nolint:gochecknoglobals
)

type SimpleURL struct {
	Scheme string
	Host   string
	Path   string
	Query  map[string][]string
}

func newSimpleURL(url *url.URL) SimpleURL {
	return SimpleURL{
		Scheme: url.Scheme,
		Host:   url.Host,
		Path:   url.EscapedPath(),
		Query:  url.Query(),
	}
}

type Request struct {
	ctx heimdall.Context

	Method   string
	URL      SimpleURL
	ClientIP []string
}

func WrapRequest(ctx heimdall.Context) *Request {
	return &Request{
		ctx:      ctx,
		Method:   ctx.RequestMethod(),
		URL:      newSimpleURL(ctx.RequestURL()),
		ClientIP: ctx.RequestClientIPs(),
	}
}

func (r *Request) Header(name string) string { return r.ctx.RequestHeader(name) }
func (r *Request) Cookie(name string) string { return r.ctx.RequestCookie(name) }

func (r *Request) Receive(function string, _ string, args []ref.Val) ref.Val {
	switch function {
	case "Header":
		if len(args) == 0 {
			return types.NewErr("no arguments provided")
		}

		name, ok := args[0].Value().(string)
		if ok {
			return types.String(r.Header(name))
		}
	case "Cookie":
		if len(args) == 0 {
			return types.NewErr("no arguments provided")
		}

		name, ok := args[0].Value().(string)
		if ok {
			return types.String(r.Cookie(name))
		}
	}

	return types.NewErr("no such function - %s", function)
}

func (r *Request) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, fmt.Errorf("%w: Request", errTypeConversion)
}

func (r *Request) ConvertToType(_ ref.Type) ref.Val { return types.NewErr("no such overload") }

func (r *Request) Equal(other ref.Val) ref.Val { return types.Bool(r == other.Value()) }

func (r *Request) Type() ref.Type { return requestType }

func (r *Request) Value() any { return r }

func (r *Request) HasTrait(trait int) bool { return r.Type().HasTrait(trait) }

func (r *Request) TypeName() string { return r.Type().TypeName() }
