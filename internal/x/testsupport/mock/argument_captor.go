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

package mock

import "github.com/stretchr/testify/mock"

type ArgumentCaptor[T any] struct {
	capturedArgs []T
}

func NewArgumentCaptor[T any](m *mock.Mock, name string) *ArgumentCaptor[T] {
	captor := &ArgumentCaptor[T]{}

	m.TestData().Set(name, captor)

	return captor
}

func (c *ArgumentCaptor[T]) Capture(val T) {
	c.capturedArgs = append(c.capturedArgs, val)
}

func (c *ArgumentCaptor[T]) Values() []T {
	return c.capturedArgs
}

func (c *ArgumentCaptor[T]) Value() T {
	var def T

	if len(c.capturedArgs)-1 >= 0 {
		return c.capturedArgs[0]
	}

	return def
}

func ArgumentCaptorFrom[T any](m *mock.Mock, name string) *ArgumentCaptor[T] {
	return m.TestData().Get(name).Data().(*ArgumentCaptor[T]) // nolint: forcetypeassert
}
