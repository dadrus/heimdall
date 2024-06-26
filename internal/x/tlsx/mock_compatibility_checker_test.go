// Code generated by mockery v2.42.1. DO NOT EDIT.

package tlsx

import (
	tls "crypto/tls"

	mock "github.com/stretchr/testify/mock"
)

// compatibilityCheckerMock is an autogenerated mock type for the compatibilityChecker type
type compatibilityCheckerMock struct {
	mock.Mock
}

type compatibilityCheckerMock_Expecter struct {
	mock *mock.Mock
}

func (_m *compatibilityCheckerMock) EXPECT() *compatibilityCheckerMock_Expecter {
	return &compatibilityCheckerMock_Expecter{mock: &_m.Mock}
}

// SupportsCertificate provides a mock function with given fields: c
func (_m *compatibilityCheckerMock) SupportsCertificate(c *tls.Certificate) error {
	ret := _m.Called(c)

	if len(ret) == 0 {
		panic("no return value specified for SupportsCertificate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*tls.Certificate) error); ok {
		r0 = rf(c)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// compatibilityCheckerMock_SupportsCertificate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SupportsCertificate'
type compatibilityCheckerMock_SupportsCertificate_Call struct {
	*mock.Call
}

// SupportsCertificate is a helper method to define mock.On call
//   - c *tls.Certificate
func (_e *compatibilityCheckerMock_Expecter) SupportsCertificate(c interface{}) *compatibilityCheckerMock_SupportsCertificate_Call {
	return &compatibilityCheckerMock_SupportsCertificate_Call{Call: _e.mock.On("SupportsCertificate", c)}
}

func (_c *compatibilityCheckerMock_SupportsCertificate_Call) Run(run func(c *tls.Certificate)) *compatibilityCheckerMock_SupportsCertificate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*tls.Certificate))
	})
	return _c
}

func (_c *compatibilityCheckerMock_SupportsCertificate_Call) Return(_a0 error) *compatibilityCheckerMock_SupportsCertificate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *compatibilityCheckerMock_SupportsCertificate_Call) RunAndReturn(run func(*tls.Certificate) error) *compatibilityCheckerMock_SupportsCertificate_Call {
	_c.Call.Return(run)
	return _c
}

// newCompatibilityCheckerMock creates a new instance of compatibilityCheckerMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newCompatibilityCheckerMock(t interface {
	mock.TestingT
	Cleanup(func())
}) *compatibilityCheckerMock {
	mock := &compatibilityCheckerMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
