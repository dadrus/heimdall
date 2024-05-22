// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	context "context"

	heimdall "github.com/dadrus/heimdall/internal/heimdall"
	mock "github.com/stretchr/testify/mock"

	rule "github.com/dadrus/heimdall/internal/rules/rule"
)

// ContextMock is an autogenerated mock type for the Context type
type ContextMock struct {
	mock.Mock
}

type ContextMock_Expecter struct {
	mock *mock.Mock
}

func (_m *ContextMock) EXPECT() *ContextMock_Expecter {
	return &ContextMock_Expecter{mock: &_m.Mock}
}

// AddCookieForUpstream provides a mock function with given fields: name, value
func (_m *ContextMock) AddCookieForUpstream(name string, value string) {
	_m.Called(name, value)
}

// ContextMock_AddCookieForUpstream_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddCookieForUpstream'
type ContextMock_AddCookieForUpstream_Call struct {
	*mock.Call
}

// AddCookieForUpstream is a helper method to define mock.On call
//   - name string
//   - value string
func (_e *ContextMock_Expecter) AddCookieForUpstream(name interface{}, value interface{}) *ContextMock_AddCookieForUpstream_Call {
	return &ContextMock_AddCookieForUpstream_Call{Call: _e.mock.On("AddCookieForUpstream", name, value)}
}

func (_c *ContextMock_AddCookieForUpstream_Call) Run(run func(name string, value string)) *ContextMock_AddCookieForUpstream_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *ContextMock_AddCookieForUpstream_Call) Return() *ContextMock_AddCookieForUpstream_Call {
	_c.Call.Return()
	return _c
}

func (_c *ContextMock_AddCookieForUpstream_Call) RunAndReturn(run func(string, string)) *ContextMock_AddCookieForUpstream_Call {
	_c.Call.Return(run)
	return _c
}

// AddHeaderForUpstream provides a mock function with given fields: name, value
func (_m *ContextMock) AddHeaderForUpstream(name string, value string) {
	_m.Called(name, value)
}

// ContextMock_AddHeaderForUpstream_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddHeaderForUpstream'
type ContextMock_AddHeaderForUpstream_Call struct {
	*mock.Call
}

// AddHeaderForUpstream is a helper method to define mock.On call
//   - name string
//   - value string
func (_e *ContextMock_Expecter) AddHeaderForUpstream(name interface{}, value interface{}) *ContextMock_AddHeaderForUpstream_Call {
	return &ContextMock_AddHeaderForUpstream_Call{Call: _e.mock.On("AddHeaderForUpstream", name, value)}
}

func (_c *ContextMock_AddHeaderForUpstream_Call) Run(run func(name string, value string)) *ContextMock_AddHeaderForUpstream_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *ContextMock_AddHeaderForUpstream_Call) Return() *ContextMock_AddHeaderForUpstream_Call {
	_c.Call.Return()
	return _c
}

func (_c *ContextMock_AddHeaderForUpstream_Call) RunAndReturn(run func(string, string)) *ContextMock_AddHeaderForUpstream_Call {
	_c.Call.Return(run)
	return _c
}

// AppContext provides a mock function with given fields:
func (_m *ContextMock) AppContext() context.Context {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for AppContext")
	}

	var r0 context.Context
	if rf, ok := ret.Get(0).(func() context.Context); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(context.Context)
		}
	}

	return r0
}

// ContextMock_AppContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AppContext'
type ContextMock_AppContext_Call struct {
	*mock.Call
}

// AppContext is a helper method to define mock.On call
func (_e *ContextMock_Expecter) AppContext() *ContextMock_AppContext_Call {
	return &ContextMock_AppContext_Call{Call: _e.mock.On("AppContext")}
}

func (_c *ContextMock_AppContext_Call) Run(run func()) *ContextMock_AppContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_AppContext_Call) Return(_a0 context.Context) *ContextMock_AppContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_AppContext_Call) RunAndReturn(run func() context.Context) *ContextMock_AppContext_Call {
	_c.Call.Return(run)
	return _c
}

// Finalize provides a mock function with given fields: backend
func (_m *ContextMock) Finalize(backend rule.Backend) error {
	ret := _m.Called(backend)

	if len(ret) == 0 {
		panic("no return value specified for Finalize")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(rule.Backend) error); ok {
		r0 = rf(backend)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ContextMock_Finalize_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Finalize'
type ContextMock_Finalize_Call struct {
	*mock.Call
}

// Finalize is a helper method to define mock.On call
//   - backend rule.Backend
func (_e *ContextMock_Expecter) Finalize(backend interface{}) *ContextMock_Finalize_Call {
	return &ContextMock_Finalize_Call{Call: _e.mock.On("Finalize", backend)}
}

func (_c *ContextMock_Finalize_Call) Run(run func(backend rule.Backend)) *ContextMock_Finalize_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(rule.Backend))
	})
	return _c
}

func (_c *ContextMock_Finalize_Call) Return(_a0 error) *ContextMock_Finalize_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Finalize_Call) RunAndReturn(run func(rule.Backend) error) *ContextMock_Finalize_Call {
	_c.Call.Return(run)
	return _c
}

// Outputs provides a mock function with given fields:
func (_m *ContextMock) Outputs() heimdall.Outputs {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Outputs")
	}

	var r0 heimdall.Outputs
	if rf, ok := ret.Get(0).(func() heimdall.Outputs); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(heimdall.Outputs)
		}
	}

	return r0
}

// ContextMock_Outputs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Outputs'
type ContextMock_Outputs_Call struct {
	*mock.Call
}

// Outputs is a helper method to define mock.On call
func (_e *ContextMock_Expecter) Outputs() *ContextMock_Outputs_Call {
	return &ContextMock_Outputs_Call{Call: _e.mock.On("Outputs")}
}

func (_c *ContextMock_Outputs_Call) Run(run func()) *ContextMock_Outputs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_Outputs_Call) Return(_a0 heimdall.Outputs) *ContextMock_Outputs_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Outputs_Call) RunAndReturn(run func() heimdall.Outputs) *ContextMock_Outputs_Call {
	_c.Call.Return(run)
	return _c
}

// Request provides a mock function with given fields:
func (_m *ContextMock) Request() *heimdall.Request {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Request")
	}

	var r0 *heimdall.Request
	if rf, ok := ret.Get(0).(func() *heimdall.Request); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*heimdall.Request)
		}
	}

	return r0
}

// ContextMock_Request_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Request'
type ContextMock_Request_Call struct {
	*mock.Call
}

// Request is a helper method to define mock.On call
func (_e *ContextMock_Expecter) Request() *ContextMock_Request_Call {
	return &ContextMock_Request_Call{Call: _e.mock.On("Request")}
}

func (_c *ContextMock_Request_Call) Run(run func()) *ContextMock_Request_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_Request_Call) Return(_a0 *heimdall.Request) *ContextMock_Request_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Request_Call) RunAndReturn(run func() *heimdall.Request) *ContextMock_Request_Call {
	_c.Call.Return(run)
	return _c
}

// SetPipelineError provides a mock function with given fields: err
func (_m *ContextMock) SetPipelineError(err error) {
	_m.Called(err)
}

// ContextMock_SetPipelineError_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetPipelineError'
type ContextMock_SetPipelineError_Call struct {
	*mock.Call
}

// SetPipelineError is a helper method to define mock.On call
//   - err error
func (_e *ContextMock_Expecter) SetPipelineError(err interface{}) *ContextMock_SetPipelineError_Call {
	return &ContextMock_SetPipelineError_Call{Call: _e.mock.On("SetPipelineError", err)}
}

func (_c *ContextMock_SetPipelineError_Call) Run(run func(err error)) *ContextMock_SetPipelineError_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(error))
	})
	return _c
}

func (_c *ContextMock_SetPipelineError_Call) Return() *ContextMock_SetPipelineError_Call {
	_c.Call.Return()
	return _c
}

func (_c *ContextMock_SetPipelineError_Call) RunAndReturn(run func(error)) *ContextMock_SetPipelineError_Call {
	_c.Call.Return(run)
	return _c
}

// Signer provides a mock function with given fields:
func (_m *ContextMock) Signer() heimdall.JWTSigner {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Signer")
	}

	var r0 heimdall.JWTSigner
	if rf, ok := ret.Get(0).(func() heimdall.JWTSigner); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(heimdall.JWTSigner)
		}
	}

	return r0
}

// ContextMock_Signer_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Signer'
type ContextMock_Signer_Call struct {
	*mock.Call
}

// Signer is a helper method to define mock.On call
func (_e *ContextMock_Expecter) Signer() *ContextMock_Signer_Call {
	return &ContextMock_Signer_Call{Call: _e.mock.On("Signer")}
}

func (_c *ContextMock_Signer_Call) Run(run func()) *ContextMock_Signer_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_Signer_Call) Return(_a0 heimdall.JWTSigner) *ContextMock_Signer_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Signer_Call) RunAndReturn(run func() heimdall.JWTSigner) *ContextMock_Signer_Call {
	_c.Call.Return(run)
	return _c
}

// NewContextMock creates a new instance of ContextMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewContextMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *ContextMock {
	mock := &ContextMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
