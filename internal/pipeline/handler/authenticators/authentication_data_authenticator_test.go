package authenticators

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestCreateAuthenticationDataAuthenticator(t *testing.T) {
	t.Parallel()

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
				t.Helper()
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
				t.Helper()
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
				t.Helper()
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
				t.Helper()
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
				t.Helper()
				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			t.Parallel()
			// WHEN
			_, err := NewAuthenticationDataAuthenticatorFromYAML(tc.config)

			// THEN
			tc.assertError(t, err)
		})
	}
}

func TestCreateAuthenticationDataAuthenticatorFromPrototypeNotAllowed(t *testing.T) {
	t.Parallel()
	// GIVEN
	p := authenticationDataAuthenticator{}

	// WHEN
	_, err := p.WithConfig([]byte{})

	// THEN
	assert.Error(t, err)
	assert.Equal(t, "reconfiguration not allowed", err.Error())
}

func TestSuccessfulExecutionOfAuthenticationDataAuthenticator(t *testing.T) {
	t.Parallel()
	// GIVEN
	subCtx := &heimdall.SubjectContext{}
	sub := &heimdall.Subject{ID: "bar"}
	ctx := context.Background()
	eResp := []byte("foo")
	authDataVal := "foobar"
	reqCtx := &MockRequestContext{}

	ept := &MockEndpoint{}
	ept.On("SendRequest", mock.Anything, mock.MatchedBy(func(r io.Reader) bool {
		val, _ := ioutil.ReadAll(r)

		return string(val) == authDataVal
	}),
	).Return(eResp, nil)

	subExtr := &MockSubjectExtractor{}
	subExtr.On("GetSubject", eResp).Return(sub, nil)

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", reqCtx).Return(authDataVal, nil)

	ada := authenticationDataAuthenticator{
		Endpoint:         ept,
		SubjectExtractor: subExtr,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := ada.Authenticate(ctx, reqCtx, subCtx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, sub, subCtx.Subject)

	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToMissingAuthData(t *testing.T) {
	t.Parallel()
	// GIVEN
	subCtx := &heimdall.SubjectContext{}
	ctx := context.Background()
	ept := &MockEndpoint{}
	subExtr := &MockSubjectExtractor{}
	failErr := errors.New("no auth data present")

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return("", failErr)

	ada := authenticationDataAuthenticator{
		Endpoint:         ept,
		SubjectExtractor: subExtr,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := ada.Authenticate(ctx, nil, subCtx)

	// THEN
	assert.Error(t, err)

	erra, ok := err.(*errorsx.ArgumentError)
	require.True(t, ok)
	assert.Equal(t, failErr, erra.Cause)

	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToEndpointError(t *testing.T) {
	t.Parallel()
	// GIVEN
	subStx := &heimdall.SubjectContext{}
	ctx := context.Background()
	authDataVal := "foobar"
	netErr := errors.New("no auth data present")
	adg := &MockAuthDataGetter{}
	ept := &MockEndpoint{}
	subExtr := &MockSubjectExtractor{}

	adg.On("GetAuthData", mock.Anything).Return(authDataVal, nil)
	ept.On("SendRequest", mock.Anything, mock.Anything).Return(nil, netErr)

	ada := authenticationDataAuthenticator{
		Endpoint:         ept,
		SubjectExtractor: subExtr,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := ada.Authenticate(ctx, nil, subStx)

	// THEN
	assert.Error(t, err)
	assert.Equal(t, netErr, err)

	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToFailedSubjectExtraction(t *testing.T) {
	t.Parallel()
	// GIVEN
	subCtx := &heimdall.SubjectContext{}
	ctx := context.Background()
	authDataVal := "foobar"
	eResp := []byte("foo")
	sgErr := errors.New("failed to extract subject")
	adg := &MockAuthDataGetter{}
	ept := &MockEndpoint{}
	subExtr := &MockSubjectExtractor{}

	adg.On("GetAuthData", mock.Anything).Return(authDataVal, nil)
	ept.On("SendRequest", mock.Anything, mock.Anything).Return(eResp, nil)
	subExtr.On("GetSubject", eResp).Return(nil, sgErr)

	ada := authenticationDataAuthenticator{
		Endpoint:         ept,
		SubjectExtractor: subExtr,
		AuthDataGetter:   adg,
	}

	// WHEN
	err := ada.Authenticate(ctx, nil, subCtx)

	// THEN
	assert.Error(t, err)
	assert.Equal(t, sgErr, err)

	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}
