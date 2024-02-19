// Code generated by mockery v2.23.1. DO NOT EDIT.

package mocks

import (
	context "context"
	time "time"

	mock "github.com/stretchr/testify/mock"
)

// CacheMock is an autogenerated mock type for the Cache type
type CacheMock struct {
	mock.Mock
}

type CacheMock_Expecter struct {
	mock *mock.Mock
}

func (_m *CacheMock) EXPECT() *CacheMock_Expecter {
	return &CacheMock_Expecter{mock: &_m.Mock}
}

// Get provides a mock function with given fields: ctx, key
func (_m *CacheMock) Get(ctx context.Context, key string) ([]byte, error) {
	ret := _m.Called(ctx, key)

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]byte, error)); ok {
		return rf(ctx, key)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []byte); ok {
		r0 = rf(ctx, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CacheMock_Get_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Get'
type CacheMock_Get_Call struct {
	*mock.Call
}

// Get is a helper method to define mock.On call
//   - ctx context.Context
//   - key string
func (_e *CacheMock_Expecter) Get(ctx interface{}, key interface{}) *CacheMock_Get_Call {
	return &CacheMock_Get_Call{Call: _e.mock.On("Get", ctx, key)}
}

func (_c *CacheMock_Get_Call) Run(run func(ctx context.Context, key string)) *CacheMock_Get_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *CacheMock_Get_Call) Return(_a0 []byte, _a1 error) *CacheMock_Get_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CacheMock_Get_Call) RunAndReturn(run func(context.Context, string) ([]byte, error)) *CacheMock_Get_Call {
	_c.Call.Return(run)
	return _c
}

// Set provides a mock function with given fields: ctx, key, value, ttl
func (_m *CacheMock) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ret := _m.Called(ctx, key, value, ttl)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []byte, time.Duration) error); ok {
		r0 = rf(ctx, key, value, ttl)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CacheMock_Set_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Set'
type CacheMock_Set_Call struct {
	*mock.Call
}

// Set is a helper method to define mock.On call
//   - ctx context.Context
//   - key string
//   - value []byte
//   - ttl time.Duration
func (_e *CacheMock_Expecter) Set(ctx interface{}, key interface{}, value interface{}, ttl interface{}) *CacheMock_Set_Call {
	return &CacheMock_Set_Call{Call: _e.mock.On("Set", ctx, key, value, ttl)}
}

func (_c *CacheMock_Set_Call) Run(run func(ctx context.Context, key string, value []byte, ttl time.Duration)) *CacheMock_Set_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].([]byte), args[3].(time.Duration))
	})
	return _c
}

func (_c *CacheMock_Set_Call) Return(_a0 error) *CacheMock_Set_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CacheMock_Set_Call) RunAndReturn(run func(context.Context, string, []byte, time.Duration) error) *CacheMock_Set_Call {
	_c.Call.Return(run)
	return _c
}

// Start provides a mock function with given fields: ctx
func (_m *CacheMock) Start(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CacheMock_Start_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Start'
type CacheMock_Start_Call struct {
	*mock.Call
}

// Start is a helper method to define mock.On call
//   - ctx context.Context
func (_e *CacheMock_Expecter) Start(ctx interface{}) *CacheMock_Start_Call {
	return &CacheMock_Start_Call{Call: _e.mock.On("Start", ctx)}
}

func (_c *CacheMock_Start_Call) Run(run func(ctx context.Context)) *CacheMock_Start_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *CacheMock_Start_Call) Return(_a0 error) *CacheMock_Start_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CacheMock_Start_Call) RunAndReturn(run func(context.Context) error) *CacheMock_Start_Call {
	_c.Call.Return(run)
	return _c
}

// Stop provides a mock function with given fields: ctx
func (_m *CacheMock) Stop(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CacheMock_Stop_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Stop'
type CacheMock_Stop_Call struct {
	*mock.Call
}

// Stop is a helper method to define mock.On call
//   - ctx context.Context
func (_e *CacheMock_Expecter) Stop(ctx interface{}) *CacheMock_Stop_Call {
	return &CacheMock_Stop_Call{Call: _e.mock.On("Stop", ctx)}
}

func (_c *CacheMock_Stop_Call) Run(run func(ctx context.Context)) *CacheMock_Stop_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *CacheMock_Stop_Call) Return(_a0 error) *CacheMock_Stop_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CacheMock_Stop_Call) RunAndReturn(run func(context.Context) error) *CacheMock_Stop_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewCacheMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewCacheMock creates a new instance of CacheMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewCacheMock(t mockConstructorTestingTNewCacheMock) *CacheMock {
	mock := &CacheMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
