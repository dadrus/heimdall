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

	err = tmpl.Execute(&buf, templateData{Subject: sub, ctx: ctx})
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

type templateData struct {
	ctx     heimdall.Context
	Subject *subject.Subject
}

func (t templateData) RequestMethod() string {
	return t.ctx.RequestMethod()
}

func (t templateData) RequestHeaders() map[string]string {
	return t.ctx.RequestHeaders()
}

func (t templateData) RequestHeader(name string) string {
	return t.ctx.RequestHeader(name)
}

func (t templateData) RequestCookie(name string) string {
	return t.ctx.RequestCookie(name)
}

func (t templateData) RequestQueryParameter(name string) string {
	return t.ctx.RequestQueryParameter(name)
}

func (t templateData) RequestURL() *url.URL {
	return t.ctx.RequestURL()
}

func (t templateData) RequestClientIPs() []string {
	return t.ctx.RequestClientIPs()
}
