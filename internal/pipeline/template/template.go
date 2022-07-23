package template

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrTemplateRender = errors.New("template error")

type Template interface {
	Render(ctx heimdall.Context, sub *subject.Subject) (string, error)
	Hash() string
}

type templateImpl struct {
	t    *template.Template
	hash string
}

func New(val string) (Template, error) {
	tmpl, err := template.New("Heimdall").
		Funcs(sprig.TxtFuncMap()).
		Funcs(template.FuncMap{"urlenc": url.QueryEscape}).
		Parse(val)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "failed to parse template").
			CausedBy(err)
	}

	hash := sha256.New()
	hash.Write([]byte(val))

	return &templateImpl{t: tmpl, hash: hex.EncodeToString(hash.Sum(nil))}, nil
}

func (t *templateImpl) Render(ctx heimdall.Context, sub *subject.Subject) (string, error) {
	var buf bytes.Buffer

	err := t.t.Execute(&buf, data{Subject: sub, ctx: ctx})
	if err != nil {
		return "", errorchain.New(ErrTemplateRender).CausedBy(err)
	}

	return buf.String(), nil
}

func (t *templateImpl) Hash() string { return t.hash }

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
