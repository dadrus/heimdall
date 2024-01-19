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

package cache

import (
	"context"

	"github.com/dadrus/heimdall/internal/cache/noop"
)

type ctxKey struct{}

// WithContext returns a copy of ctx with cache associated. If a Cache instance
// is already in the context, the ctx is not updated.
func WithContext(ctx context.Context, cch Cache) context.Context {
	if known, ok := ctx.Value(ctxKey{}).(Cache); ok {
		if known == cch {
			// Do not store same cache.
			return ctx
		}
	}

	return context.WithValue(ctx, ctxKey{}, cch)
}

// Ctx returns the Cache associated with the ctx. If no cache is associated, an instance is
// returned, which does nothing.
func Ctx(ctx context.Context) Cache {
	if c, ok := ctx.Value(ctxKey{}).(Cache); ok {
		return c
	}

	return &noop.Cache{}
}
