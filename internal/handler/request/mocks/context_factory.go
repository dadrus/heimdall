// Code generated by mockery v2.23.1. DO NOT EDIT.

package mocks

import (
	http "net/http"

	request "github.com/dadrus/heimdall/internal/handler/request"
	mock "github.com/stretchr/testify/mock"
)

// ContextFactoryMock is an autogenerated mock type for the ContextFactory type
type ContextFactoryMock struct {
	mock.Mock
}

type ContextFactoryMock_Expecter struct {
	mock *mock.Mock
}

func (_m *ContextFactoryMock) EXPECT() *ContextFactoryMock_Expecter {
	return &ContextFactoryMock_Expecter{mock: &_m.Mock}
}

// Create provides a mock function with given fields: rw, req
func (_m *ContextFactoryMock) Create(rw http.ResponseWriter, req *http.Request) request.Context {
	ret := _m.Called(rw, req)

	var r0 request.Context
	if rf, ok := ret.Get(0).(func(http.ResponseWriter, *http.Request) request.Context); ok {
		r0 = rf(rw, req)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(request.Context)
		}
	}

	return r0
}

// ContextFactoryMock_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type ContextFactoryMock_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - rw http.ResponseWriter
//   - req *http.Request
func (_e *ContextFactoryMock_Expecter) Create(rw interface{}, req interface{}) *ContextFactoryMock_Create_Call {
	return &ContextFactoryMock_Create_Call{Call: _e.mock.On("Create", rw, req)}
}

func (_c *ContextFactoryMock_Create_Call) Run(run func(rw http.ResponseWriter, req *http.Request)) *ContextFactoryMock_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.ResponseWriter), args[1].(*http.Request))
	})
	return _c
}

func (_c *ContextFactoryMock_Create_Call) Return(_a0 request.Context) *ContextFactoryMock_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextFactoryMock_Create_Call) RunAndReturn(run func(http.ResponseWriter, *http.Request) request.Context) *ContextFactoryMock_Create_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewContextFactoryMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewContextFactoryMock creates a new instance of ContextFactoryMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewContextFactoryMock(t mockConstructorTestingTNewContextFactoryMock) *ContextFactoryMock {
	mock := &ContextFactoryMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
