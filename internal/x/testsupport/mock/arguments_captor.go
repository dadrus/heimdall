package mock

import "github.com/stretchr/testify/mock"

type ArgumentsCaptor struct {
	capturedArgs []mock.Arguments
}

func NewArgumentsCaptor(m *mock.Mock, name string) *ArgumentsCaptor {
	captor := &ArgumentsCaptor{}

	m.TestData().Set(name, captor)

	return captor
}

func (c *ArgumentsCaptor) Capture(args mock.Arguments) {
	c.capturedArgs = append(c.capturedArgs, args)
}

func (c *ArgumentsCaptor) Values(call int) mock.Arguments {
	if len(c.capturedArgs)-1 >= call {
		return c.capturedArgs[call]
	}

	return nil
}

func ArgumentsCaptorFrom(m *mock.Mock, name string) *ArgumentsCaptor {
	return m.TestData().Get(name).Data().(*ArgumentsCaptor) // nolint: forcetypeassert
}
