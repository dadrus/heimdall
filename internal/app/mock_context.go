// Code generated by mockery v2.42.1. DO NOT EDIT.

package app

import (
	config "github.com/dadrus/heimdall/internal/config"
	certificate "github.com/dadrus/heimdall/internal/otel/metrics/certificate"

	keyholder "github.com/dadrus/heimdall/internal/keyholder"

	mock "github.com/stretchr/testify/mock"

	validation "github.com/dadrus/heimdall/internal/validation"

	watcher "github.com/dadrus/heimdall/internal/watcher"

	zerolog "github.com/rs/zerolog"
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

// CertificateObserver provides a mock function with given fields:
func (_m *ContextMock) CertificateObserver() certificate.Observer {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for CertificateObserver")
	}

	var r0 certificate.Observer
	if rf, ok := ret.Get(0).(func() certificate.Observer); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(certificate.Observer)
		}
	}

	return r0
}

// ContextMock_CertificateObserver_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CertificateObserver'
type ContextMock_CertificateObserver_Call struct {
	*mock.Call
}

// CertificateObserver is a helper method to define mock.On call
func (_e *ContextMock_Expecter) CertificateObserver() *ContextMock_CertificateObserver_Call {
	return &ContextMock_CertificateObserver_Call{Call: _e.mock.On("CertificateObserver")}
}

func (_c *ContextMock_CertificateObserver_Call) Run(run func()) *ContextMock_CertificateObserver_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_CertificateObserver_Call) Return(_a0 certificate.Observer) *ContextMock_CertificateObserver_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_CertificateObserver_Call) RunAndReturn(run func() certificate.Observer) *ContextMock_CertificateObserver_Call {
	_c.Call.Return(run)
	return _c
}

// Config provides a mock function with given fields:
func (_m *ContextMock) Config() *config.Configuration {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Config")
	}

	var r0 *config.Configuration
	if rf, ok := ret.Get(0).(func() *config.Configuration); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*config.Configuration)
		}
	}

	return r0
}

// ContextMock_Config_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Config'
type ContextMock_Config_Call struct {
	*mock.Call
}

// Config is a helper method to define mock.On call
func (_e *ContextMock_Expecter) Config() *ContextMock_Config_Call {
	return &ContextMock_Config_Call{Call: _e.mock.On("Config")}
}

func (_c *ContextMock_Config_Call) Run(run func()) *ContextMock_Config_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_Config_Call) Return(_a0 *config.Configuration) *ContextMock_Config_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Config_Call) RunAndReturn(run func() *config.Configuration) *ContextMock_Config_Call {
	_c.Call.Return(run)
	return _c
}

// KeyHolderRegistry provides a mock function with given fields:
func (_m *ContextMock) KeyHolderRegistry() keyholder.Registry {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for KeyHolderRegistry")
	}

	var r0 keyholder.Registry
	if rf, ok := ret.Get(0).(func() keyholder.Registry); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(keyholder.Registry)
		}
	}

	return r0
}

// ContextMock_KeyHolderRegistry_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeyHolderRegistry'
type ContextMock_KeyHolderRegistry_Call struct {
	*mock.Call
}

// KeyHolderRegistry is a helper method to define mock.On call
func (_e *ContextMock_Expecter) KeyHolderRegistry() *ContextMock_KeyHolderRegistry_Call {
	return &ContextMock_KeyHolderRegistry_Call{Call: _e.mock.On("KeyHolderRegistry")}
}

func (_c *ContextMock_KeyHolderRegistry_Call) Run(run func()) *ContextMock_KeyHolderRegistry_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_KeyHolderRegistry_Call) Return(_a0 keyholder.Registry) *ContextMock_KeyHolderRegistry_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_KeyHolderRegistry_Call) RunAndReturn(run func() keyholder.Registry) *ContextMock_KeyHolderRegistry_Call {
	_c.Call.Return(run)
	return _c
}

// Logger provides a mock function with given fields:
func (_m *ContextMock) Logger() zerolog.Logger {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Logger")
	}

	var r0 zerolog.Logger
	if rf, ok := ret.Get(0).(func() zerolog.Logger); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(zerolog.Logger)
	}

	return r0
}

// ContextMock_Logger_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Logger'
type ContextMock_Logger_Call struct {
	*mock.Call
}

// Logger is a helper method to define mock.On call
func (_e *ContextMock_Expecter) Logger() *ContextMock_Logger_Call {
	return &ContextMock_Logger_Call{Call: _e.mock.On("Logger")}
}

func (_c *ContextMock_Logger_Call) Run(run func()) *ContextMock_Logger_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_Logger_Call) Return(_a0 zerolog.Logger) *ContextMock_Logger_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Logger_Call) RunAndReturn(run func() zerolog.Logger) *ContextMock_Logger_Call {
	_c.Call.Return(run)
	return _c
}

// Validator provides a mock function with given fields:
func (_m *ContextMock) Validator() validation.Validator {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Validator")
	}

	var r0 validation.Validator
	if rf, ok := ret.Get(0).(func() validation.Validator); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(validation.Validator)
		}
	}

	return r0
}

// ContextMock_Validator_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Validator'
type ContextMock_Validator_Call struct {
	*mock.Call
}

// Validator is a helper method to define mock.On call
func (_e *ContextMock_Expecter) Validator() *ContextMock_Validator_Call {
	return &ContextMock_Validator_Call{Call: _e.mock.On("Validator")}
}

func (_c *ContextMock_Validator_Call) Run(run func()) *ContextMock_Validator_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_Validator_Call) Return(_a0 validation.Validator) *ContextMock_Validator_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Validator_Call) RunAndReturn(run func() validation.Validator) *ContextMock_Validator_Call {
	_c.Call.Return(run)
	return _c
}

// Watcher provides a mock function with given fields:
func (_m *ContextMock) Watcher() watcher.Watcher {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Watcher")
	}

	var r0 watcher.Watcher
	if rf, ok := ret.Get(0).(func() watcher.Watcher); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(watcher.Watcher)
		}
	}

	return r0
}

// ContextMock_Watcher_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Watcher'
type ContextMock_Watcher_Call struct {
	*mock.Call
}

// Watcher is a helper method to define mock.On call
func (_e *ContextMock_Expecter) Watcher() *ContextMock_Watcher_Call {
	return &ContextMock_Watcher_Call{Call: _e.mock.On("Watcher")}
}

func (_c *ContextMock_Watcher_Call) Run(run func()) *ContextMock_Watcher_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ContextMock_Watcher_Call) Return(_a0 watcher.Watcher) *ContextMock_Watcher_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ContextMock_Watcher_Call) RunAndReturn(run func() watcher.Watcher) *ContextMock_Watcher_Call {
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
