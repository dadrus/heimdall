package authenticators

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
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
			_, err := newAuthenticationDataAuthenticator(decode(tc.config))

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
	authDataVal := "foobar"
	subjectData := []byte(`{"foo":"bar", "bar":"foo"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		receivedAuthData := r.Header.Get("Dummy")
		assert.Equal(t, authDataVal, receivedAuthData)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(subjectData)))

		_, err := w.Write(subjectData)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(&DummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectExtractor{}
	subExtr.On("GetSubject", subjectData).Return(sub, nil)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
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
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToMissingAuthData(t *testing.T) {
	t.Parallel()
	// GIVEN
	subExtr := &testsupport.MockSubjectExtractor{}

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return(nil, testsupport.ErrTestPurpose)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: "foobar.local"},
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
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToEndpointError(t *testing.T) {
	t.Parallel()
	// GIVEN
	authDataVal := "foobar"

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(DummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectExtractor{}

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: "foobar.local"},
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Authenticate(ctx)

	// THEN
	assert.Error(t, err)
	assert.True(t, errors.Is(err, heimdall.ErrCommunication))

	assert.Nil(t, sub)

	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToFailedSubjectExtraction(t *testing.T) {
	t.Parallel()
	// GIVEN
	authDataVal := "foobar"
	subjectData := []byte(`{"foo":"bar", "bar":"foo"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		receivedAuthData := r.Header.Get("Dummy")
		assert.Equal(t, authDataVal, receivedAuthData)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(subjectData)))

		_, err := w.Write(subjectData)
		assert.NoError(t, err)
	}))
	defer srv.Close()

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(DummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectExtractor{}
	subExtr.On("GetSubject", subjectData).Return(nil, testsupport.ErrTestPurpose)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Authenticate(ctx)

	// THEN
	assert.Error(t, err)
	assert.True(t, errors.Is(err, testsupport.ErrTestPurpose))

	assert.Nil(t, sub)

	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}
