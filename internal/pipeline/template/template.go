package template

import (
	"bytes"
	"net/url"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
)

type Template string

func (t Template) Render(ctx heimdall.Context, sub *subject.Subject) (string, error) {
	tmpl, err := template.New("Heimdall").
		Funcs(sprig.TxtFuncMap()).
		Funcs(template.FuncMap{"urlenc": url.QueryEscape}).
		Parse(string(t))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, data{Subject: sub, ctx: ctx})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

type data struct {
	ctx     heimdall.Context
	Subject *subject.Subject
}

func (t data) RequestMethod() string {
	return t.ctx.RequestMethod()
}

func (t data) RequestURL() string {
	return t.ctx.RequestURL().String()
}

func (t data) RequestClientIPs() []string {
	return t.ctx.RequestClientIPs()
}

func (t data) RequestHeader(name string) string {
	return t.ctx.RequestHeader(name)
}

func (t data) RequestCookie(name string) string {
	return t.ctx.RequestCookie(name)
}

func (t data) RequestQueryParameter(name string) string {
	return t.ctx.RequestQueryParameter(name)
}
