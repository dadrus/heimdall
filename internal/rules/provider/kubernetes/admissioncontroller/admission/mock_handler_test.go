// Code generated by mockery v2.23.1. DO NOT EDIT.

package admission

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// HandlerMock is an autogenerated mock type for the Handler type
type HandlerMock struct {
	mock.Mock
}

type HandlerMock_Expecter struct {
	mock *mock.Mock
}

func (_m *HandlerMock) EXPECT() *HandlerMock_Expecter {
	return &HandlerMock_Expecter{mock: &_m.Mock}
}

// Handle provides a mock function with given fields: _a0, _a1
func (_m *HandlerMock) Handle(_a0 context.Context, _a1 *Request) *Response {
	ret := _m.Called(_a0, _a1)

	var r0 *Response
	if rf, ok := ret.Get(0).(func(context.Context, *Request) *Response); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Response)
		}
	}

	return r0
}

// HandlerMock_Handle_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Handle'
type HandlerMock_Handle_Call struct {
	*mock.Call
}

// Handle is a helper method to define mock.On call
//   - _a0 context.Context
//   - _a1 *Request
func (_e *HandlerMock_Expecter) Handle(_a0 interface{}, _a1 interface{}) *HandlerMock_Handle_Call {
	return &HandlerMock_Handle_Call{Call: _e.mock.On("Handle", _a0, _a1)}
}

func (_c *HandlerMock_Handle_Call) Run(run func(_a0 context.Context, _a1 *Request)) *HandlerMock_Handle_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*Request))
	})
	return _c
}

func (_c *HandlerMock_Handle_Call) Return(_a0 *Response) *HandlerMock_Handle_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *HandlerMock_Handle_Call) RunAndReturn(run func(context.Context, *Request) *Response) *HandlerMock_Handle_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewHandlerMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewHandlerMock creates a new instance of HandlerMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewHandlerMock(t mockConstructorTestingTNewHandlerMock) *HandlerMock {
	mock := &HandlerMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
