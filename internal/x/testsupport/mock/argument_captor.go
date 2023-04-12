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
