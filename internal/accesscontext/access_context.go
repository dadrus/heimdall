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

package accesscontext

import (
	"context"

	"github.com/dadrus/heimdall/internal/subject"
)

type ctxKey struct{}

type accessContext struct {
	err     error
	subject subject.Subject
}

func New(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, &accessContext{})
}

func Error(ctx context.Context) error {
	if c, ok := ctx.Value(ctxKey{}).(*accessContext); ok {
		return c.err
	}

	return nil
}

func SetError(ctx context.Context, err error) {
	if c, ok := ctx.Value(ctxKey{}).(*accessContext); ok {
		c.err = err
	}
}

func Subject(ctx context.Context) subject.Subject {
	if c, ok := ctx.Value(ctxKey{}).(*accessContext); ok {
		return c.subject
	}

	return subject.Subject{}
}

func SetSubject(ctx context.Context, sub subject.Subject) {
	if c, ok := ctx.Value(ctxKey{}).(*accessContext); ok {
		c.subject = sub
	}
}
