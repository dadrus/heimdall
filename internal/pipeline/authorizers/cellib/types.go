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

	requestType = types.NewTypeValue("cellib.Request", traits.ReceiverType)   //nolint:gochecknoglobals
	urlType     = types.NewTypeValue("cellib.SimpleURL", traits.ReceiverType) //nolint:gochecknoglobals
)

type URL struct {
	url.URL
}

func (u *URL) Receive(function string, _ string, args []ref.Val) ref.Val {
	switch function {
	case "String":
		return types.String(u.String())
	case "Query":
		return types.NewDynamicMap(types.DefaultTypeAdapter, u.Query())
	}

	return types.NewErr("no such function - %s", function)
}

func (u *URL) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, fmt.Errorf("%w: Request", errTypeConversion)
}

func (u *URL) ConvertToType(_ ref.Type) ref.Val { return types.NewErr("no such overload") }
func (u *URL) Equal(other ref.Val) ref.Val      { return types.Bool(u == other.Value()) }
func (u *URL) Type() ref.Type                   { return urlType }
func (u *URL) Value() any                       { return u }

type Request struct {
	ctx heimdall.Context

	Method   string
	URL      *URL
	ClientIP []string
}

func WrapRequest(ctx heimdall.Context) *Request {
	return &Request{
		ctx:      ctx,
		Method:   ctx.RequestMethod(),
		URL:      &URL{URL: *ctx.RequestURL()},
		ClientIP: ctx.RequestClientIPs(),
	}
}

func (r *Request) Header(name string) string { return r.ctx.RequestHeader(name) }
func (r *Request) Cookie(name string) string { return r.ctx.RequestCookie(name) }

func (r *Request) Receive(function string, _ string, args []ref.Val) ref.Val {
	switch function {
	// CEL ensures, the function is called with the expected number of arguments
	// and with expected type (string)
	case "Header":
		// nolint: forcetypeassert
		return types.String(r.Header(args[0].Value().(string)))
	case "Cookie":
		// nolint: forcetypeassert
		return types.String(r.Cookie(args[0].Value().(string)))
	}

	return types.NewErr("no such function - %s", function)
}

func (r *Request) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, fmt.Errorf("%w: Request", errTypeConversion)
}

func (r *Request) ConvertToType(_ ref.Type) ref.Val { return types.NewErr("no such overload") }
func (r *Request) Equal(other ref.Val) ref.Val      { return types.Bool(r == other.Value()) }
func (r *Request) Type() ref.Type                   { return requestType }
func (r *Request) Value() any                       { return r }
