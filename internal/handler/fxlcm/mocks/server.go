// Code generated by mockery v2.23.1. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"

	net "net"
)

// ServerMock is an autogenerated mock type for the Server type
type ServerMock struct {
	mock.Mock
}

type ServerMock_Expecter struct {
	mock *mock.Mock
}

func (_m *ServerMock) EXPECT() *ServerMock_Expecter {
	return &ServerMock_Expecter{mock: &_m.Mock}
}

// Serve provides a mock function with given fields: l
func (_m *ServerMock) Serve(l net.Listener) error {
	ret := _m.Called(l)

	var r0 error
	if rf, ok := ret.Get(0).(func(net.Listener) error); ok {
		r0 = rf(l)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ServerMock_Serve_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Serve'
type ServerMock_Serve_Call struct {
	*mock.Call
}

// Serve is a helper method to define mock.On call
//   - l net.Listener
func (_e *ServerMock_Expecter) Serve(l interface{}) *ServerMock_Serve_Call {
	return &ServerMock_Serve_Call{Call: _e.mock.On("Serve", l)}
}

func (_c *ServerMock_Serve_Call) Run(run func(l net.Listener)) *ServerMock_Serve_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(net.Listener))
	})
	return _c
}

func (_c *ServerMock_Serve_Call) Return(_a0 error) *ServerMock_Serve_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ServerMock_Serve_Call) RunAndReturn(run func(net.Listener) error) *ServerMock_Serve_Call {
	_c.Call.Return(run)
	return _c
}

// Shutdown provides a mock function with given fields: ctx
func (_m *ServerMock) Shutdown(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ServerMock_Shutdown_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Shutdown'
type ServerMock_Shutdown_Call struct {
	*mock.Call
}

// Shutdown is a helper method to define mock.On call
//   - ctx context.Context
func (_e *ServerMock_Expecter) Shutdown(ctx interface{}) *ServerMock_Shutdown_Call {
	return &ServerMock_Shutdown_Call{Call: _e.mock.On("Shutdown", ctx)}
}

func (_c *ServerMock_Shutdown_Call) Run(run func(ctx context.Context)) *ServerMock_Shutdown_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *ServerMock_Shutdown_Call) Return(_a0 error) *ServerMock_Shutdown_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ServerMock_Shutdown_Call) RunAndReturn(run func(context.Context) error) *ServerMock_Shutdown_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewServerMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewServerMock creates a new instance of ServerMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewServerMock(t mockConstructorTestingTNewServerMock) *ServerMock {
	mock := &ServerMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
