package authenticators

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/cache"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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
  subject_id_from: some_template`),
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
  subject_id_from: some_template`),
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
  subject_id_from: some_template`),
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
  subject_id_from: some_template`),
			assertError: func(t *testing.T, err error) {
				t.Helper()
				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			_, err = newAuthenticationDataAuthenticator(conf)

			// THEN
			tc.assertError(t, err)
		})
	}
}

func TestCreateAuthenticationDataAuthenticatorFromPrototype(t *testing.T) {
	// nolint
	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *authenticationDataAuthenticator,
			configured *authenticationDataAuthenticator)
	}{
		{
			uc: "prototype config without cache configured and empty target config",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template`),
			config: []byte{},
			assert: func(t *testing.T, err error, prototype *authenticationDataAuthenticator,
				configured *authenticationDataAuthenticator) {
				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "prototype config without cache, config with cache",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template`),
			config: []byte(`cache_ttl: 5s`),
			assert: func(t *testing.T, err error, prototype *authenticationDataAuthenticator,
				configured *authenticationDataAuthenticator) {
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.se, configured.se)
				assert.Nil(t, prototype.ttl)
				assert.NotEqual(t, prototype.ttl, *configured.ttl)
				assert.Equal(t, 5*time.Second, *configured.ttl)
			},
		},
		{
			uc: "prototype config with cache, config with cache",
			prototypeConfig: []byte(`
identity_info_endpoint:
  url: http://test.com
  method: POST
authentication_data_source:
  - header: foo-header
session:
  subject_id_from: some_template
cache_ttl: 5s`),
			config: []byte(`
cache_ttl: 15s`),
			assert: func(t *testing.T, err error, prototype *authenticationDataAuthenticator,
				configured *authenticationDataAuthenticator) {
				require.NoError(t, err)

				assert.Equal(t, prototype.e, configured.e)
				assert.Equal(t, prototype.adg, configured.adg)
				assert.Equal(t, prototype.se, configured.se)
				assert.NotEqual(t, prototype.ttl, configured.ttl)
				assert.Equal(t, 15*time.Second, *configured.ttl)
				assert.Equal(t, 5*time.Second, *prototype.ttl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newAuthenticationDataAuthenticator(pc)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			ada, ok := auth.(*authenticationDataAuthenticator)
			require.True(t, ok)

			tc.assert(t, err, prototype, ada)
		})
	}
}

func TestSuccessfulExecutionOfAuthenticationDataAuthenticatorWithoutCacheUsage(t *testing.T) {
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

	cch := &testsupport.MockCache{}

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(&dummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectFactory{}
	subExtr.On("CreateSubject", subjectData).Return(sub, nil)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	rSub, err := ada.Execute(ctx)

	// THEN
	assert.NoError(t, err)
	assert.NotNil(t, rSub)
	assert.Equal(t, sub, rSub)

	ctx.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
	cch.AssertExpectations(t)
}

func TestSuccessfulExecutionOfAuthenticationDataAuthenticatorWithSubjectInfoFromCache(t *testing.T) {
	t.Parallel()

	sub := &subject.Subject{ID: "bar"}
	authDataVal := "foobar"
	subjectData := []byte(`{"foo":"bar", "bar":"foo"}`)
	subjectInfoTTL := 5 * time.Second

	cch := &testsupport.MockCache{}
	cch.On("Get", mock.Anything).Return(subjectData)

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(&dummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectFactory{}
	subExtr.On("CreateSubject", subjectData).Return(sub, nil)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: "foobar.local", Method: http.MethodGet},
		se:  subExtr,
		adg: adg,
		ttl: &subjectInfoTTL,
	}

	// WHEN
	rSub, err := ada.Execute(ctx)

	// THEN
	assert.NoError(t, err)
	assert.NotNil(t, rSub)
	assert.Equal(t, sub, rSub)

	ctx.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
	cch.AssertExpectations(t)
}

func TestSuccessfulExecutionOfAuthenticationDataAuthenticatorWithCacheMiss(t *testing.T) {
	t.Parallel()
	// GIVEN

	sub := &subject.Subject{ID: "bar"}
	authDataVal := "foobar"
	subjectData := []byte(`{"foo":"bar", "bar":"foo"}`)
	subjectInfoTTL := 5 * time.Second

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

	cch := &testsupport.MockCache{}
	cch.On("Get", mock.Anything).Return(nil)
	cch.On("Set", mock.Anything, subjectData, subjectInfoTTL)

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(cache.WithContext(context.Background(), cch))

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(&dummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectFactory{}
	subExtr.On("CreateSubject", subjectData).Return(sub, nil)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
		se:  subExtr,
		adg: adg,
		ttl: &subjectInfoTTL,
	}

	// WHEN
	rSub, err := ada.Execute(ctx)

	// THEN
	assert.NoError(t, err)
	assert.NotNil(t, rSub)
	assert.Equal(t, sub, rSub)

	ctx.AssertExpectations(t)
	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
	cch.AssertExpectations(t)
}

func TestAuthenticationDataAuthenticatorExecutionFailsDueToMissingAuthData(t *testing.T) {
	t.Parallel()
	// GIVEN
	subExtr := &testsupport.MockSubjectFactory{}

	ctx := &testsupport.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return(nil, testsupport.ErrTestPurpose)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: "foobar.local"},
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Execute(ctx)

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

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectFactory{}

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: "foobar.local"},
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Execute(ctx)

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

	adg := &mockAuthDataGetter{}
	adg.On("GetAuthData", ctx).Return(dummyAuthData{Val: authDataVal}, nil)

	subExtr := &testsupport.MockSubjectFactory{}
	subExtr.On("CreateSubject", subjectData).Return(nil, testsupport.ErrTestPurpose)

	ada := authenticationDataAuthenticator{
		e:   endpoint.Endpoint{URL: srv.URL, Method: http.MethodGet},
		se:  subExtr,
		adg: adg,
	}

	// WHEN
	sub, err := ada.Execute(ctx)

	// THEN
	assert.Error(t, err)
	assert.True(t, errors.Is(err, testsupport.ErrTestPurpose))

	assert.Nil(t, sub)

	subExtr.AssertExpectations(t)
	adg.AssertExpectations(t)
}
