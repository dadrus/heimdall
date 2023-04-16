// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrTemplateRender = errors.New("template error")

type Template interface {
	Render(ctx heimdall.Context, sub *subject.Subject, values map[string]string) (string, error)
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
		Funcs(template.FuncMap{"urlenc": urlEncode}).
		Parse(val)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "failed to parse template").
			CausedBy(err)
	}

	hash := sha256.New()
	hash.Write([]byte(val))

	return &templateImpl{t: tmpl, hash: hash.Sum(nil)}, nil
}

func (t *templateImpl) Render(ctx heimdall.Context, sub *subject.Subject, values map[string]string) (string, error) {
	var buf bytes.Buffer

	tplData := data{Subject: sub, Values: values}

	if ctx != nil {
		tplData.Request = WrapRequest(ctx)
	}

	err := t.t.Execute(&buf, tplData)
	if err != nil {
		return "", errorchain.New(ErrTemplateRender).CausedBy(err)
	}

	return buf.String(), nil
}

func (t *templateImpl) Hash() []byte { return t.hash }

func urlEncode(value any) string {
	switch t := value.(type) {
	case string:
		return url.QueryEscape(t)
	case fmt.Stringer:
		return url.QueryEscape(t.String())
	default:
		return ""
	}
}
