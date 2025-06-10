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

type ArgumentCaptor2[T1 any, T2 any] struct {
	capturedArgs1 []T1
	capturedArgs2 []T2
}

func NewArgumentCaptor2[T1 any, T2 any](m *mock.Mock, name string) *ArgumentCaptor2[T1, T2] {
	captor := &ArgumentCaptor2[T1, T2]{}

	m.TestData().Set(name, captor)

	return captor
}

func (c *ArgumentCaptor2[T1, T2]) Capture(val1 T1, val2 T2) {
	c.capturedArgs1 = append(c.capturedArgs1, val1)
	c.capturedArgs2 = append(c.capturedArgs2, val2)
}

func (c *ArgumentCaptor2[T1, T2]) Values() ([]T1, []T2) {
	return c.capturedArgs1, c.capturedArgs2
}

func (c *ArgumentCaptor2[T1, T2]) Value() (T1, T2) {
	var (
		def1 T1
		def2 T2
	)

	if len(c.capturedArgs1)-1 >= 0 {
		def1 = c.capturedArgs1[0]
	}

	if len(c.capturedArgs2)-1 >= 0 {
		def2 = c.capturedArgs2[0]
	}

	return def1, def2
}

func ArgumentCaptor2From[T1 any, T2 any](m *mock.Mock, name string) *ArgumentCaptor2[T1, T2] {
	return m.TestData().Get(name).Data().(*ArgumentCaptor2[T1, T2]) // nolint: forcetypeassert
}

type ArgumentCaptor3[T1 any, T2 any, T3 any] struct {
	capturedArgs1 []T1
	capturedArgs2 []T2
	capturedArgs3 []T3
}

func NewArgumentCaptor3[T1 any, T2 any, T3 any](m *mock.Mock, name string) *ArgumentCaptor3[T1, T2, T3] {
	captor := &ArgumentCaptor3[T1, T2, T3]{}

	m.TestData().Set(name, captor)

	return captor
}

func (c *ArgumentCaptor3[T1, T2, T3]) Capture(val1 T1, val2 T2, val3 T3) {
	c.capturedArgs1 = append(c.capturedArgs1, val1)
	c.capturedArgs2 = append(c.capturedArgs2, val2)
	c.capturedArgs3 = append(c.capturedArgs3, val3)
}

func (c *ArgumentCaptor3[T1, T2, T3]) Values() ([]T1, []T2, []T3) {
	return c.capturedArgs1, c.capturedArgs2, c.capturedArgs3
}

func (c *ArgumentCaptor3[T1, T2, T3]) Value() (T1, T2, T3) {
	var (
		def1 T1
		def2 T2
		def3 T3
	)

	if len(c.capturedArgs1)-1 >= 0 {
		def1 = c.capturedArgs1[0]
	}

	if len(c.capturedArgs2)-1 >= 0 {
		def2 = c.capturedArgs2[0]
	}

	if len(c.capturedArgs3)-1 >= 0 {
		def3 = c.capturedArgs3[0]
	}

	return def1, def2, def3
}

func ArgumentCaptor3From[T1 any, T2 any, T3 any](m *mock.Mock, name string) *ArgumentCaptor3[T1, T2, T3] {
	return m.TestData().Get(name).Data().(*ArgumentCaptor3[T1, T2, T3]) // nolint: forcetypeassert
}
