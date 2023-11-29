// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package exporters

import (
	"context"
	"errors"
	"sync"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrDuplicateRegistration = errors.New("duplicate registration")

type FactoryFunc[T any] func(ctx context.Context) (T, error)

type registry[T any] struct {
	mu    sync.Mutex
	names map[string]FactoryFunc[T]
}

func (r *registry[T]) load(key string) (FactoryFunc[T], bool) {
	r.mu.Lock()
	f, ok := r.names[key]
	r.mu.Unlock()

	return f, ok
}

func (r *registry[T]) store(key string, value FactoryFunc[T]) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.names == nil {
		r.names = map[string]FactoryFunc[T]{key: value}

		return nil
	}

	if _, ok := r.names[key]; ok {
		return errorchain.NewWithMessage(ErrDuplicateRegistration, key)
	}

	r.names[key] = value

	return nil
}
