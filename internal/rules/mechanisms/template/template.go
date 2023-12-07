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
	"reflect"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

var (
	ErrTemplateRender = errors.New("template error")
	ErrInvalidType    = errors.New("invalid type")
)

type Template interface {
	Render(values map[string]any) (string, error)
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
		Funcs(template.FuncMap{
			"urlenc":   urlEncode,
			"atIndex":  atIndex,
			"parseJWT": parseJWT,
		}).
		Parse(val)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration, "failed to parse template").
			CausedBy(err)
	}

	hash := sha256.New()
	hash.Write(stringx.ToBytes(val))

	return &templateImpl{t: tmpl, hash: hash.Sum(nil)}, nil
}

func (t *templateImpl) Render(values map[string]any) (string, error) {
	var buf bytes.Buffer

	err := t.t.Execute(&buf, values)
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

func parseJWT(value any) (interface{}, error) {
	var jwtInput string
	switch tp := value.(type) {
	case string:
		jwtInput = tp
	case fmt.Stringer:
		jwtInput = tp.String()
	default:
		return nil, fmt.Errorf("cannot parse jwt from type %s: %w", tp, ErrInvalidType)
	}

	token, err := jwt.ParseSigned(jwtInput)
	if err != nil {
		return nil, fmt.Errorf("jwt parse failed: %w", err)
	}

	// return the claims data as untyped object
	tokenData := map[string]interface{}{}
	if err := token.UnsafeClaimsWithoutVerification(&tokenData); err != nil {
		return nil, fmt.Errorf("failed to decode token claims: %w", err)
	}

	return tokenData, nil
}

func atIndex(pos int, list interface{}) (interface{}, error) {
	tp := reflect.TypeOf(list).Kind()
	switch tp {
	case reflect.Slice, reflect.Array:
		l2 := reflect.ValueOf(list)

		length := l2.Len()
		if length == 0 {
			return nil, nil // nolint: nilnil
		}

		if pos >= 0 && pos >= length {
			// nolint: goerr113
			return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
		}

		if pos < 0 && (-pos-1) >= length {
			// nolint: goerr113
			return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
		}

		if pos >= 0 {
			return l2.Index(pos).Interface(), nil
		}

		return l2.Index(length + pos).Interface(), nil

	default:
		// nolint: goerr113
		return nil, fmt.Errorf("cannot find at on type %s", tp)
	}
}
