package authenticators

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/pipeline/handler/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func TestCreateAuthenticationDataAuthenticator(t *testing.T) {
	t.Parallel()

	decode := func(data []byte) map[string]interface{} {
		var res map[string]interface{}

		err := yaml.Unmarshal(data, &res)
		assert.NoError(t, err)

		return res
	}

	// nolint
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
			_, err := NewAuthenticationDataAuthenticator(decode(tc.config))

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
	_, err := p.WithConfig(nil)

	// THEN
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

func TestSuccessfulExecutionOfAuthenticationDataAuthenticator(t *testing.T) {
	t.Parallel()
	// GIVEN
	sub := &subject.Subject{ID: "bar"}
	eResp := []byte("foo")
	authDataVal := "foobar"

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	ept := &testsupport.MockEndpoint{}
	ept.On("SendRequest", mock.Anything, mock.MatchedBy(func(r io.Reader) bool {
		val, _ := ioutil.ReadAll(r)

		return string(val) == authDataVal
	}),
	).Return(eResp, nil)

	subExtr := &testsupport.MockSubjectExtractor{}
	subExtr.On("GetSubject", eResp).Return(sub, nil)

	adg := &testsupport.MockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(authDataVal, nil)

	ada := authenticationDataAuthenticator{
		e:   ept,
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	rSub, err := ada.Authenticate(ctx)

	// THEN
	assert.NoError(t, err)
	assert.NotNil(t, rSub)
	assert.Equal(t, sub, rSub)

	ctx.AssertExpectations(t)
	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToMissingAuthData(t *testing.T) {
	t.Parallel()
	// GIVEN
	ept := &testsupport.MockEndpoint{}
	subExtr := &testsupport.MockSubjectExtractor{}

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &testsupport.MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return("", testsupport.ErrTestPurpose)

	ada := authenticationDataAuthenticator{
		e:   ept,
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Authenticate(ctx)

	// THEN
	assert.Error(t, err)
	assert.Nil(t, sub)

	var erc *errorchain.ErrorChain

	assert.ErrorAs(t, err, &erc)
	assert.ErrorIs(t, erc, testsupport.ErrTestPurpose)

	ctx.AssertExpectations(t)
	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToEndpointError(t *testing.T) {
	t.Parallel()
	// GIVEN
	authDataVal := "foobar"

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &testsupport.MockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(authDataVal, nil)

	ept := &testsupport.MockEndpoint{}
	ept.On("SendRequest", mock.Anything, mock.Anything).Return(nil, testsupport.ErrTestPurpose)

	subExtr := &testsupport.MockSubjectExtractor{}

	ada := authenticationDataAuthenticator{
		e:   ept,
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Authenticate(ctx)

	// THEN
	assert.Error(t, err)
	assert.True(t, errors.Is(err, testsupport.ErrTestPurpose))

	assert.Nil(t, sub)

	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToFailedSubjectExtraction(t *testing.T) {
	t.Parallel()
	// GIVEN
	authDataVal := "foobar"
	eResp := []byte("foo")

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &testsupport.MockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(authDataVal, nil)

	ept := &testsupport.MockEndpoint{}
	ept.On("SendRequest", mock.Anything, mock.Anything).Return(eResp, nil)

	subExtr := &testsupport.MockSubjectExtractor{}
	subExtr.On("GetSubject", eResp).Return(nil, testsupport.ErrTestPurpose)

	ada := authenticationDataAuthenticator{
		e:   ept,
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Authenticate(ctx)

	// THEN
	assert.Error(t, err)
	assert.True(t, errors.Is(err, testsupport.ErrTestPurpose))

	assert.Nil(t, sub)

	ept.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}
