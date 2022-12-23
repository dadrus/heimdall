package template

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/url"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrTemplateRender = errors.New("template error")

type Template interface {
	Render(ctx heimdall.Context, sub *subject.Subject) (string, error)
	Hash() []byte
}

type templateImpl struct {
	t    *template.Template
	hash []byte
}

func New(val string) (Template, error) {
	funcMap := sprig.TxtFuncMap()
	delete(funcMap, "env")
	delete(funcMap, "expandenv")

	tmpl, err := template.New("Heimdall").
		Funcs(funcMap).
		Funcs(template.FuncMap{"urlenc": url.QueryEscape}).
		Parse(val)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "failed to parse template").
			CausedBy(err)
	}

	hash := sha256.New()
	hash.Write([]byte(val))

	return &templateImpl{t: tmpl, hash: hash.Sum(nil)}, nil
}

func (t *templateImpl) Render(ctx heimdall.Context, sub *subject.Subject) (string, error) {
	var (
		buf bytes.Buffer
		req *Request
	)

	if ctx != nil {
		req = WrapRequest(ctx)
	}

	err := t.t.Execute(&buf, data{Subject: sub, Request: req})
	if err != nil {
		return "", errorchain.New(ErrTemplateRender).CausedBy(err)
	}

	return buf.String(), nil
}

func (t *templateImpl) Hash() []byte { return t.hash }
