package authenticators

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestCreateAuthenticationDataAuthenticator(t *testing.T) {
	for _, tc := range []struct {
		uc          string
		config      []byte
		assertError func(t *testing.T, err error)
	}{
		{
			uc: "missing session config",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
authentication_data_source:
  - header: foo-header`),
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			uc: "missing url config",
			config: []byte(`
authentication_data_source:
  - header: foo-header
session:
  subject_from: some_template`),
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			uc: "missing authentication data source config",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
session:
  subject_from: some_template`),
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			uc: "config with undefined fields",
			config: []byte(`
foo: bar
identity_info_endpoint:
  url: http://test.com
session:
  subject_from: some_template`),
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			uc: "valid configuration",
			config: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_from: some_template`),
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			_, err := NewAuthenticationDataAuthenticatorFromYAML(tc.config)

			// THEN
			tc.assertError(t, err)
		})
	}
}

func TestCreateAuthenticationDataAuthenticatorFromPrototypeGivenEmptyConfig(t *testing.T) {
	// GIVEN
	p := authenticationDataAuthenticator{}

	// WHEN
	_, err := p.WithConfig([]byte{})

	// THEN
	assert.Error(t, err)
	assert.Equal(t, "reconfiguration not allowed", err.Error())
}

func TestSuccessfulExecutionOfAuthenticationDataAuthenticator(t *testing.T) {
	// GIVEN
	sc := &heimdall.SubjectContext{}
	sub := &heimdall.Subject{Id: "bar"}
	ctx := context.Background()
	eResp := json.RawMessage("foo")
	authDataVal := "foobar"

	e := &MockEndpoint{}
	e.On("SendRequest", mock.Anything, mock.MatchedBy(func(r io.Reader) bool {
		val, _ := ioutil.ReadAll(r)
		return string(val) == authDataVal
	}),
	).Return(eResp, nil)

	se := &MockSubjectExtractor{}
	se.On("GetSubject", eResp).Return(sub, nil)

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return(authDataVal, nil)

	a := authenticationDataAuthenticator{
		Endpoint:         e,
		SubjectExtractor: se,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := a.Authenticate(ctx, nil, sc)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, sub, sc.Subject)

	e.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToMissingAuthData(t *testing.T) {
	// GIVEN
	sc := &heimdall.SubjectContext{}
	ctx := context.Background()
	e := &MockEndpoint{}
	se := &MockSubjectExtractor{}
	failErr := errors.New("no auth data present")

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return("", failErr)

	a := authenticationDataAuthenticator{
		Endpoint:         e,
		SubjectExtractor: se,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := a.Authenticate(ctx, nil, sc)

	// THEN
	assert.Error(t, err)
	assert.IsType(t, &errorsx.ArgumentError{}, err)
	erra := err.(*errorsx.ArgumentError)
	assert.Equal(t, failErr, erra.Cause)

	e.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToEndpointError(t *testing.T) {
	// GIVEN
	sc := &heimdall.SubjectContext{}
	ctx := context.Background()
	authDataVal := "foobar"
	netErr := errors.New("no auth data present")

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return(authDataVal, nil)
	e := &MockEndpoint{}
	e.On("SendRequest", mock.Anything, mock.Anything).Return(nil, netErr)
	se := &MockSubjectExtractor{}

	a := authenticationDataAuthenticator{
		Endpoint:         e,
		SubjectExtractor: se,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := a.Authenticate(ctx, nil, sc)

	// THEN
	assert.Error(t, err)
	assert.Equal(t, netErr, err)

	e.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToFailedSubjectExtraction(t *testing.T) {
	// GIVEN
	sc := &heimdall.SubjectContext{}
	ctx := context.Background()
	authDataVal := "foobar"
	eResp := json.RawMessage("foo")
	sgErr := errors.New("failed to extract subject")

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return(authDataVal, nil)
	e := &MockEndpoint{}
	e.On("SendRequest", mock.Anything, mock.Anything).Return(eResp, nil)
	se := &MockSubjectExtractor{}
	se.On("GetSubject", eResp).Return(nil, sgErr)

	a := authenticationDataAuthenticator{
		Endpoint:         e,
		SubjectExtractor: se,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := a.Authenticate(ctx, nil, sc)

	// THEN
	assert.Error(t, err)
	assert.Equal(t, sgErr, err)

	e.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}
