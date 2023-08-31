// Code generated by mockery v2.23.1. DO NOT EDIT.

package mocks

import (
	heimdall "github.com/dadrus/heimdall/internal/heimdall"
	mock "github.com/stretchr/testify/mock"

	url "net/url"
)

// ExecutorMock is an autogenerated mock type for the Executor type
type ExecutorMock struct {
	mock.Mock
}

type ExecutorMock_Expecter struct {
	mock *mock.Mock
}

func (_m *ExecutorMock) EXPECT() *ExecutorMock_Expecter {
	return &ExecutorMock_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: ctx, requireURL
func (_m *ExecutorMock) Execute(ctx heimdall.Context, requireURL bool) (*url.URL, error) {
	ret := _m.Called(ctx, requireURL)

	var r0 *url.URL
	var r1 error
	if rf, ok := ret.Get(0).(func(heimdall.Context, bool) (*url.URL, error)); ok {
		return rf(ctx, requireURL)
	}
	if rf, ok := ret.Get(0).(func(heimdall.Context, bool) *url.URL); ok {
		r0 = rf(ctx, requireURL)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*url.URL)
		}
	}

	if rf, ok := ret.Get(1).(func(heimdall.Context, bool) error); ok {
		r1 = rf(ctx, requireURL)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ExecutorMock_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type ExecutorMock_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - ctx heimdall.Context
//   - requireURL bool
func (_e *ExecutorMock_Expecter) Execute(ctx interface{}, requireURL interface{}) *ExecutorMock_Execute_Call {
	return &ExecutorMock_Execute_Call{Call: _e.mock.On("Execute", ctx, requireURL)}
}

func (_c *ExecutorMock_Execute_Call) Run(run func(ctx heimdall.Context, requireURL bool)) *ExecutorMock_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(heimdall.Context), args[1].(bool))
	})
	return _c
}

func (_c *ExecutorMock_Execute_Call) Return(_a0 *url.URL, _a1 error) *ExecutorMock_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ExecutorMock_Execute_Call) RunAndReturn(run func(heimdall.Context, bool) (*url.URL, error)) *ExecutorMock_Execute_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewExecutorMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewExecutorMock creates a new instance of ExecutorMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewExecutorMock(t mockConstructorTestingTNewExecutorMock) *ExecutorMock {
	mock := &ExecutorMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
