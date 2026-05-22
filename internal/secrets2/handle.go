// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package secrets2

import (
	"context"
)

type handleBinding[T any] interface {
	get(ctx context.Context) (T, bool)
	subscribe(cb UpdateFunc[T]) func()
}

type cleanupRegistry interface {
	registerCleanup(cleanup func())
}

type noopCleanupRegistry struct{}

func (noopCleanupRegistry) registerCleanup(func()) {}

type handle[T any] struct {
	binding  handleBinding[T]
	cleanups cleanupRegistry
}

func newHandle[T any](
	binding handleBinding[T],
	cleanups cleanupRegistry,
) *handle[T] {
	return &handle[T]{
		binding:  binding,
		cleanups: cleanups,
	}
}

func (h *handle[T]) Get(ctx context.Context) (T, bool) {
	return h.binding.get(ctx)
}

func (h *handle[T]) OnUpdate(cb UpdateFunc[T]) {
	if cb == nil {
		return
	}

	h.cleanups.registerCleanup(h.binding.subscribe(cb))
}

var (
	_ SecretHandle            = (*handle[Secret])(nil)
	_ SecretSetHandle         = (*handle[[]Secret])(nil)
	_ CredentialsHandle       = (*handle[Credentials])(nil)
	_ CertificateBundleHandle = (*handle[CertificateBundle])(nil)
)
