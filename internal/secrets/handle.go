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

package secrets

import (
	"context"
)

type handleBinding[T any] interface {
	awaitReady(ctx context.Context) error
	peek() (T, bool)
	subscribe(cb UpdateFunc[T]) func()
}

type handleOwner interface {
	registerCleanup(cleanup func())
	registerReadiness(await func(context.Context) error)
}

type handle[T any] struct {
	b handleBinding[T]
	o handleOwner
}

func newHandle[T any](
	binding handleBinding[T],
	ho handleOwner,
) *handle[T] {
	ho.registerReadiness(binding.awaitReady)

	return &handle[T]{
		b: binding,
		o: ho,
	}
}

func (h *handle[T]) Get() (T, bool) {
	return h.b.peek()
}

func (h *handle[T]) OnUpdate(cb UpdateFunc[T]) {
	if cb == nil {
		return
	}

	h.o.registerCleanup(h.b.subscribe(cb))
}

func (h *handle[T]) registerReadiness(await func(context.Context) error) {
	h.o.registerReadiness(await)
}

var (
	_ SecretHandle            = (*handle[Secret])(nil)
	_ SecretSetHandle         = (*handle[[]Secret])(nil)
	_ CredentialsHandle       = (*handle[Credentials])(nil)
	_ CertificateBundleHandle = (*handle[CertificateBundle])(nil)
)
