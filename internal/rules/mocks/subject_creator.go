// Code generated by mockery v2.23.1. DO NOT EDIT.

package mocks

import (
	heimdall "github.com/dadrus/heimdall/internal/heimdall"
	mock "github.com/stretchr/testify/mock"

	subject "github.com/dadrus/heimdall/internal/rules/mechanisms/subject"
)

// SubjectCreatorMock is an autogenerated mock type for the subjectCreator type
type SubjectCreatorMock struct {
	mock.Mock
}

type SubjectCreatorMock_Expecter struct {
	mock *mock.Mock
}

func (_m *SubjectCreatorMock) EXPECT() *SubjectCreatorMock_Expecter {
	return &SubjectCreatorMock_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: _a0
func (_m *SubjectCreatorMock) Execute(_a0 heimdall.Context) (*subject.Subject, error) {
	ret := _m.Called(_a0)

	var r0 *subject.Subject
	var r1 error
	if rf, ok := ret.Get(0).(func(heimdall.Context) (*subject.Subject, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(heimdall.Context) *subject.Subject); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*subject.Subject)
		}
	}

	if rf, ok := ret.Get(1).(func(heimdall.Context) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SubjectCreatorMock_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type SubjectCreatorMock_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - _a0 heimdall.Context
func (_e *SubjectCreatorMock_Expecter) Execute(_a0 interface{}) *SubjectCreatorMock_Execute_Call {
	return &SubjectCreatorMock_Execute_Call{Call: _e.mock.On("Execute", _a0)}
}

func (_c *SubjectCreatorMock_Execute_Call) Run(run func(_a0 heimdall.Context)) *SubjectCreatorMock_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(heimdall.Context))
	})
	return _c
}

func (_c *SubjectCreatorMock_Execute_Call) Return(_a0 *subject.Subject, _a1 error) *SubjectCreatorMock_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *SubjectCreatorMock_Execute_Call) RunAndReturn(run func(heimdall.Context) (*subject.Subject, error)) *SubjectCreatorMock_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// IsFallbackOnErrorAllowed provides a mock function with given fields:
func (_m *SubjectCreatorMock) IsFallbackOnErrorAllowed() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// SubjectCreatorMock_IsFallbackOnErrorAllowed_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsFallbackOnErrorAllowed'
type SubjectCreatorMock_IsFallbackOnErrorAllowed_Call struct {
	*mock.Call
}

// IsFallbackOnErrorAllowed is a helper method to define mock.On call
func (_e *SubjectCreatorMock_Expecter) IsFallbackOnErrorAllowed() *SubjectCreatorMock_IsFallbackOnErrorAllowed_Call {
	return &SubjectCreatorMock_IsFallbackOnErrorAllowed_Call{Call: _e.mock.On("IsFallbackOnErrorAllowed")}
}

func (_c *SubjectCreatorMock_IsFallbackOnErrorAllowed_Call) Run(run func()) *SubjectCreatorMock_IsFallbackOnErrorAllowed_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *SubjectCreatorMock_IsFallbackOnErrorAllowed_Call) Return(_a0 bool) *SubjectCreatorMock_IsFallbackOnErrorAllowed_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *SubjectCreatorMock_IsFallbackOnErrorAllowed_Call) RunAndReturn(run func() bool) *SubjectCreatorMock_IsFallbackOnErrorAllowed_Call {
	_c.Call.Return(run)
	return _c
}

type mockConstructorTestingTNewSubjectCreatorMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewSubjectCreatorMock creates a new instance of SubjectCreatorMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewSubjectCreatorMock(t mockConstructorTestingTNewSubjectCreatorMock) *SubjectCreatorMock {
	mock := &SubjectCreatorMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
