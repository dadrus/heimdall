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
	"context"
	"crypto/sha256"
	"errors"
	"maps"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var ErrTemplateRender = errors.New("template error")

type Template interface {
	Render(values map[string]any) (string, error)
	Hash() []byte
	String() string
}

type templateImpl struct { //nolint:recvcheck
	// recvcheck disabled by intention, as otherwise validations, which require Stringer implementation,
	// but receive a value (not a pointer) do not work

	t         *template.Template
	orig      string
	hash      []byte
	informers map[secrets.Reference]*secrets.SecretInformer[string]
}

func New(val string, opts ...Option) (Template, error) {
	cfg := applyOptions(opts...)

	funcMap := sprig.TxtFuncMap()
	delete(funcMap, "env")
	delete(funcMap, "expandenv")

	informers := make(map[secrets.Reference]*secrets.SecretInformer[string])

	tmpl, err := template.New(cfg.name).
		Funcs(funcMap).
		Funcs(template.FuncMap{
			"urlenc":  urlEncode,
			"atIndex": atIndex,
			"secret":  secret(informers),
		}).
		Parse(val)
	if err != nil {
		return nil, errorchain.NewWithMessage(pipeline.ErrConfiguration, "failed to parse template").
			CausedBy(err)
	}

	createdInformers, err := createSecretInformers(
		context.Background(),
		cfg.resolver,
		tmpl,
		cfg.secretsForbidden,
	)
	if err != nil {
		return nil, err
	}

	maps.Copy(informers, createdInformers)

	hash := sha256.New()
	hash.Write(stringx.ToBytes(val))

	var result [sha256.Size]byte

	return templateImpl{
		t:         tmpl,
		orig:      val,
		hash:      hash.Sum(result[:0]),
		informers: informers,
	}, nil
}

func Must(value string, opts ...Option) Template {
	tpl, err := New(value, opts...)
	if err != nil {
		panic(err)
	}

	return tpl
}

func (t templateImpl) Render(values map[string]any) (string, error) {
	var buf bytes.Buffer

	err := t.t.Execute(&buf, values)
	if err != nil {
		return "", errorchain.New(ErrTemplateRender).CausedBy(err)
	}

	return buf.String(), nil
}

func (t templateImpl) Hash() []byte { return t.hash }

func (t templateImpl) String() string { return t.orig }
