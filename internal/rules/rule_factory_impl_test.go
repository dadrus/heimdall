// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"net/url"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	mocks2 "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/mocks"
	mocks4 "github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers/mocks"
	mocks5 "github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers/mocks"
	mocks6 "github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers/mocks"
	mocks7 "github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers/mocks"
	mocks3 "github.com/dadrus/heimdall/internal/rules/mechanisms/mocks"
	"github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestRuleFactoryNew(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config                   *config.Configuration
		enforceSecureDefaultRule bool
		configureMocks           func(t *testing.T, mhf *mocks3.MechanismFactoryMock)
		assert                   func(t *testing.T, err error, ruleFactory *ruleFactory)
	}{
		"new factory without default rule": {
			config: &config.Configuration{},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ruleFactory)
				assert.Nil(t, ruleFactory.DefaultRule())
			},
		},
		"new factory with default rule with unsupported object in execute definition": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"foo": "bar"},
					},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported configuration")
			},
		},
		"new factory with default rule with unsupported object in error handler definition": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					ErrorHandler: []config.MechanismConfig{
						{"foo": "bar"},
					},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported configuration")
			},
		},
		"new factory with malformed default rule, where authenticator loading happens after subject handlers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"contextualizer": "bar", "id": "baz"},
						{"authenticator": "foo", "id": "zab"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateContextualizer(mock.Anything, "bar", "baz", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "an authenticator")
			},
		},
		"new factory with malformed default rule, where authenticator loading happens after finalizers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar", "id": "baz"},
						{"authenticator": "foo", "id": "zab"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "bar", "baz", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "an authenticator")
			},
		},
		"new factory with default rule, where authenticator loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authenticator": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "foo", "", mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with malformed default rule, where authorizer loading happens after finalizers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar"},
						{"authorizer": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "bar", "", mock.Anything).Return(nil, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "before an authorizer")
			},
		},
		"new factory with default rule, where authorizer loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authorizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthorizer(mock.Anything, "foo", "", mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with malformed default rule, where contextualizer loading happens after finalizers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar"},
						{"contextualizer": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "bar", "", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "before a contextualizer")
			},
		},
		"new factory with default rule, where contextualizer loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"contextualizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateContextualizer(mock.Anything, "foo", "", mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with default rule, where finalizer loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"finalizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "foo", "", mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with default rule, where error_handler loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					ErrorHandler: []config.MechanismConfig{{"error_handler": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateErrorHandler(mock.Anything, "foo", "", mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with empty default rule": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no authenticator")
			},
		},
		"new factory with insecure default rule, but enforced security settings": {
			enforceSecureDefaultRule: true,
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				am := mocks2.NewAuthenticatorMock(t)
				am.EXPECT().IsInsecure().Return(true)

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", "", mock.Anything).
					Return(am, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "insecure default rule")
			},
		},
		"new factory with not security enforced default rule, configured with all required elements": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar", "id": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				auth := mocks2.NewAuthenticatorMock(t)
				auth.EXPECT().IsInsecure().Return(true)
				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", "foo", mock.Anything).
					Return(auth, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleFactory)
				assert.NotNil(t, ruleFactory.DefaultRule())
				assert.Equal(t, ruleFactory.defaultRule, ruleFactory.DefaultRule())

				defRule := ruleFactory.defaultRule
				assert.True(t, defRule.isDefault)
				assert.Equal(t, "default", defRule.id)
				assert.Equal(t, "config", defRule.srcID)
				assert.Equal(t, config2.EncodedSlashesOff, defRule.slashesHandling)
				assert.Len(t, defRule.sc, 1)
				assert.Empty(t, defRule.sh)
				assert.Empty(t, defRule.fi)
				assert.Empty(t, defRule.eh)
			},
		},
		"new factory with default rule, configured with all possible elements": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar", "id": "1"},
						{"contextualizer": "foo", "id": "2"},
						{"authorizer": "zab", "id": "3"},
						{"finalizer": "baz", "id": "4"},
					},
					ErrorHandler: []config.MechanismConfig{
						{"error_handler": "foobar", "id": "1"},
						{"error_handler": "barfoo", "id": "2"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				auth := mocks2.NewAuthenticatorMock(t)
				auth.EXPECT().IsInsecure().Return(false)
				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", "1", mock.Anything).
					Return(auth, nil)
				mhf.EXPECT().CreateFinalizer(mock.Anything, "baz", "4", mock.Anything).
					Return(nil, nil)
				mhf.EXPECT().CreateAuthorizer(mock.Anything, "zab", "3", mock.Anything).
					Return(nil, nil)
				mhf.EXPECT().CreateContextualizer(mock.Anything, "foo", "2", mock.Anything).
					Return(nil, nil)
				mhf.EXPECT().CreateErrorHandler(mock.Anything, "foobar", "1", mock.Anything).
					Return(nil, nil)
				mhf.EXPECT().CreateErrorHandler(mock.Anything, "barfoo", "2", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleFactory)
				assert.NotNil(t, ruleFactory.DefaultRule())
				assert.Equal(t, ruleFactory.defaultRule, ruleFactory.DefaultRule())

				defRule := ruleFactory.defaultRule
				assert.True(t, defRule.isDefault)
				assert.Equal(t, "default", defRule.id)
				assert.Equal(t, "config", defRule.srcID)
				assert.Equal(t, config2.EncodedSlashesOff, defRule.slashesHandling)
				assert.Len(t, defRule.sc, 1)
				assert.Len(t, defRule.sh, 2)
				assert.Len(t, defRule.fi, 1)
				assert.Len(t, defRule.eh, 2)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks3.MechanismFactoryMock) { t.Helper() })

			handlerFactory := mocks3.NewMechanismFactoryMock(t)
			configureMocks(t, handlerFactory)

			// WHEN
			factory, err := NewRuleFactory(
				handlerFactory,
				tc.config,
				config.DecisionMode,
				log.Logger,
				config.SecureDefaultRule(tc.enforceSecureDefaultRule),
			)

			// THEN
			var (
				impl *ruleFactory
				ok   bool
			)

			if err == nil {
				impl, ok = factory.(*ruleFactory)
				require.True(t, ok)
			}

			// THEN
			tc.assert(t, err, impl)
		})
	}
}

func TestRuleFactoryCreateRule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opMode         config.OperationMode
		config         config2.Rule
		defaultRule    *ruleImpl
		configureMocks func(t *testing.T, mhf *mocks3.MechanismFactoryMock)
		assert         func(t *testing.T, err error, rul *ruleImpl)
	}{
		"in proxy mode without forward_to definition": {
			opMode: config.ProxyMode,
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "requires forward_to")
			},
		},
		"with error while creating method matcher": {
			config: config2.Rule{
				ID: "foobar",
				Matcher: config2.Matcher{
					Routes:  []config2.Route{{Path: "/foo/bar"}},
					Methods: []string{""},
				},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).Return(&mocks2.AuthenticatorMock{}, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "methods list contains empty values")
			},
		},
		"with error while creating route path params matcher": {
			config: config2.Rule{
				ID: "foobar",
				Matcher: config2.Matcher{
					Routes: []config2.Route{
						{
							Path:       "/foo/:bar",
							PathParams: []config2.ParameterMatcher{{Name: "bar", Type: "foo", Value: "baz"}},
						},
					},
				},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo", "id": "1"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "1", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating route '/foo/:bar'")
			},
		},
		"with error while creating execute pipeline": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{{"authenticator": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorContains(t, err, "test error")
			},
		},
		"with error while creating on_error pipeline": {
			config: config2.Rule{
				ID:           "foobar",
				Matcher:      config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				ErrorHandler: []config.MechanismConfig{{"error_handler": "foo", "id": "bar"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateErrorHandler("test", "foo", "bar", mock.Anything).
					Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorContains(t, err, "test error")
			},
		},
		"without default rule and without any execute configuration": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no authenticator defined")
			},
		},
		"without default rule and minimum required configuration in decision mode": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesOff, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())
				assert.Len(t, rul.sc, 1)
				assert.Empty(t, rul.sh)
				assert.Empty(t, rul.fi)
				assert.Empty(t, rul.eh)
			},
		},
		"without default rule and minimum required configuration in proxy mode": {
			opMode: config.ProxyMode,
			config: config2.Rule{
				ID:      "foobar",
				Backend: &config2.Backend{Host: "foo.bar"},
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesOff, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())
				assert.Len(t, rul.sc, 1)
				assert.Empty(t, rul.sh)
				assert.Empty(t, rul.fi)
				assert.Empty(t, rul.eh)
				assert.NotNil(t, rul.backend)
			},
		},
		"with default rule and regular rule with id and a single route only": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
			},
			defaultRule: &ruleImpl{
				sc: compositeSubjectCreator{&mocks.SubjectCreatorMock{}},
				sh: compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				fi: compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				eh: compositeErrorHandler{&mocks.ErrorHandlerMock{}},
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())
				assert.Len(t, rul.sc, 1)
				assert.Len(t, rul.sh, 1)
				assert.Len(t, rul.fi, 1)
				assert.Len(t, rul.eh, 1)
			},
		},
		"with default rule and with all attributes defined by the regular rule itself in decision mode": {
			config: config2.Rule{
				ID: "foobar",
				Matcher: config2.Matcher{
					Routes: []config2.Route{
						{
							Path:       "/foo/:resource",
							PathParams: []config2.ParameterMatcher{{Name: "resource", Type: "regex", Value: "(bar|baz)"}},
						},
						{
							Path:       "/bar/:resource",
							PathParams: []config2.ParameterMatcher{{Name: "resource", Type: "glob", Value: "{a,b}"}},
						},
					},
					Scheme:  "https",
					Methods: []string{"BAR", "BAZ"},
					Hosts:   []config2.HostMatcher{{Type: "glob", Value: "**.example.com"}},
				},
				EncodedSlashesHandling: config2.EncodedSlashesOnNoDecode,
				Execute: []config.MechanismConfig{
					{"authenticator": "foo", "id": "1"},
					{"contextualizer": "bar", "id": "2"},
					{"authorizer": "zab", "id": "3"},
					{"finalizer": "baz", "id": "4"},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo", "id": "5"},
				},
			},
			defaultRule: &ruleImpl{
				sc: compositeSubjectCreator{&mocks.SubjectCreatorMock{}},
				sh: compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				fi: compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				eh: compositeErrorHandler{&mocks.ErrorHandlerMock{}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "1", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
				mhf.EXPECT().CreateContextualizer("test", "bar", "2", mock.Anything).
					Return(&mocks5.ContextualizerMock{}, nil)
				mhf.EXPECT().CreateAuthorizer("test", "zab", "3", mock.Anything).
					Return(&mocks4.AuthorizerMock{}, nil)
				mhf.EXPECT().CreateFinalizer("test", "baz", "4", mock.Anything).
					Return(&mocks7.FinalizerMock{}, nil)
				mhf.EXPECT().CreateErrorHandler("test", "foo", "5", mock.Anything).
					Return(&mocks6.ErrorHandlerMock{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesOnNoDecode, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 2)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/:resource", rul.Routes()[0].Path())
				assert.Equal(t, rul, rul.Routes()[1].Rule())
				assert.Equal(t, "/bar/:resource", rul.Routes()[1].Path())

				// nil checks above mean the responses from the mockHandlerFactory are used
				// and not the values from the default rule
				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])
				require.Len(t, rul.sh, 2)
				assert.NotNil(t, rul.sh[0])
				assert.NotNil(t, rul.sh[1])
				require.Len(t, rul.fi, 1)
				assert.NotNil(t, rul.fi[0])
				require.Len(t, rul.eh, 1)
				assert.NotNil(t, rul.eh[0])
			},
		},
		"with default rule and with all attributes defined by the rule itself in proxy mode": {
			opMode: config.ProxyMode,
			config: config2.Rule{
				ID: "foobar",
				Matcher: config2.Matcher{
					Routes: []config2.Route{
						{
							Path:       "/foo/:resource",
							PathParams: []config2.ParameterMatcher{{Name: "resource", Type: "regex", Value: "(bar|baz)"}},
						},
						{
							Path:       "/bar/:resource",
							PathParams: []config2.ParameterMatcher{{Name: "resource", Type: "glob", Value: "{a,b}"}},
						},
					},
					Scheme:  "https",
					Methods: []string{"BAR", "BAZ"},
					Hosts:   []config2.HostMatcher{{Type: "glob", Value: "**.example.com"}},
				},
				EncodedSlashesHandling: config2.EncodedSlashesOn,
				Backend: &config2.Backend{
					Host: "bar.foo",
					URLRewriter: &config2.URLRewriter{
						Scheme:              "https",
						PathPrefixToCut:     "/foo",
						PathPrefixToAdd:     "/baz",
						QueryParamsToRemove: []string{"bar"},
					},
				},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo", "id": 1},
					{"contextualizer": "bar", "id": 2},
					{"authorizer": "zab", "id": 3},
					{"finalizer": "baz", "id": false},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo", "id": true},
				},
			},
			defaultRule: &ruleImpl{
				sc: compositeSubjectCreator{&mocks.SubjectCreatorMock{}},
				sh: compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				fi: compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				eh: compositeErrorHandler{&mocks.ErrorHandlerMock{}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "1", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
				mhf.EXPECT().CreateContextualizer("test", "bar", "2", mock.Anything).
					Return(&mocks5.ContextualizerMock{}, nil)
				mhf.EXPECT().CreateAuthorizer("test", "zab", "3", mock.Anything).
					Return(&mocks4.AuthorizerMock{}, nil)
				mhf.EXPECT().CreateFinalizer("test", "baz", "false", mock.Anything).
					Return(&mocks7.FinalizerMock{}, nil)
				mhf.EXPECT().CreateErrorHandler("test", "foo", "true", mock.Anything).
					Return(&mocks6.ErrorHandlerMock{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesOn, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 2)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/:resource", rul.Routes()[0].Path())
				assert.Equal(t, rul, rul.Routes()[1].Rule())
				assert.Equal(t, "/bar/:resource", rul.Routes()[1].Path())
				assert.Equal(t, "https://bar.foo/baz/bar?foo=bar", rul.backend.CreateURL(&url.URL{
					Scheme:   "http",
					Host:     "foo.bar:8888",
					Path:     "/foo/bar",
					RawQuery: url.Values{"bar": []string{"foo"}, "foo": []string{"bar"}}.Encode(),
				}).String())

				// nil checks above mean the responses from the mockHandlerFactory are used
				// and not the values from the default rule
				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])
				require.Len(t, rul.sh, 2)
				assert.NotNil(t, rul.sh[0])
				assert.NotNil(t, rul.sh[1])
				require.Len(t, rul.fi, 1)
				assert.NotNil(t, rul.fi[0])
				require.Len(t, rul.eh, 1)
				assert.NotNil(t, rul.eh[0])
				assert.NotNil(t, rul.backend)
			},
		},
		"with conditional execution configuration type error in the regular pipeline": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"finalizer": "bar", "if": 1},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unexpected type")
			},
		},
		"with empty conditional execution configuration": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"finalizer": "bar", "if": ""},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "empty execution condition")
			},
		},
		"with conditional execution for some mechanisms": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"authorizer": "bar", "if": "false"},
					{"contextualizer": "bar", "if": "true"},
					{"authorizer": "baz"},
					{"finalizer": "bar", "if": "true"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
				mhf.EXPECT().CreateAuthorizer("test", mock.Anything, "", mock.Anything).
					Return(&mocks4.AuthorizerMock{}, nil).Times(2)
				mhf.EXPECT().CreateContextualizer("test", "bar", "", mock.Anything).
					Return(&mocks5.ContextualizerMock{}, nil)
				mhf.EXPECT().CreateFinalizer("test", "bar", "", mock.Anything).
					Return(&mocks7.FinalizerMock{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())

				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])

				require.Len(t, rul.sh, 3)

				assert.NotNil(t, rul.sh[0])
				sh, ok := rul.sh[0].(*conditionalSubjectHandler)
				require.True(t, ok)
				assert.IsType(t, &celExecutionCondition{}, sh.c)

				assert.NotNil(t, rul.sh[1])
				sh, ok = rul.sh[1].(*conditionalSubjectHandler)
				require.True(t, ok)
				assert.IsType(t, &celExecutionCondition{}, sh.c)

				assert.NotNil(t, rul.sh[2])
				sh, ok = rul.sh[2].(*conditionalSubjectHandler)
				require.True(t, ok)
				assert.IsType(t, defaultExecutionCondition{}, sh.c)

				require.Len(t, rul.fi, 1)
				un, ok := rul.fi[0].(*conditionalSubjectHandler)
				require.True(t, ok)
				assert.IsType(t, &celExecutionCondition{}, un.c)

				require.Empty(t, rul.eh)
			},
		},
		"with bad conditional expression in the error pipeline": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo", "id": 1},
					{"authorizer": "bar", "id": 2},
					{"finalizer": "baz", "id": 3},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo", "id": 4, "if": "true", "config": map[string]any{}},
					{"error_handler": "bar", "id": 5, "if": 1, "config": map[string]any{}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "1", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
				mhf.EXPECT().CreateAuthorizer("test", "bar", "2", mock.Anything).
					Return(&mocks4.AuthorizerMock{}, nil)
				mhf.EXPECT().CreateFinalizer("test", "baz", "3", mock.Anything).
					Return(&mocks7.FinalizerMock{}, nil)
				mhf.EXPECT().CreateErrorHandler("test", "foo", "4", config.MechanismConfig{}).
					Return(&mocks6.ErrorHandlerMock{}, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unexpected type")
			},
		},
		"with conditional execution for error handler": {
			config: config2.Rule{
				ID:      "foobar",
				Matcher: config2.Matcher{Routes: []config2.Route{{Path: "/foo/bar"}}},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"authorizer": "bar"},
					{"finalizer": "baz"},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo", "if": "true", "config": map[string]any{}},
					{"error_handler": "bar", "if": "false", "config": map[string]any{}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.MechanismFactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", "", mock.Anything).
					Return(&mocks2.AuthenticatorMock{}, nil)
				mhf.EXPECT().CreateAuthorizer("test", "bar", "", mock.Anything).
					Return(&mocks4.AuthorizerMock{}, nil)
				mhf.EXPECT().CreateFinalizer("test", "baz", "", mock.Anything).
					Return(&mocks7.FinalizerMock{}, nil)
				mhf.EXPECT().CreateErrorHandler("test", "foo", "", config.MechanismConfig{}).Return(&mocks6.ErrorHandlerMock{}, nil)
				mhf.EXPECT().CreateErrorHandler("test", "bar", "", config.MechanismConfig{}).Return(&mocks6.ErrorHandlerMock{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())

				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])

				require.Len(t, rul.sh, 1)

				assert.NotNil(t, rul.sh[0])
				sh, ok := rul.sh[0].(*conditionalSubjectHandler)
				require.True(t, ok)
				assert.IsType(t, defaultExecutionCondition{}, sh.c)

				require.Len(t, rul.fi, 1)
				un, ok := rul.fi[0].(*conditionalSubjectHandler)
				require.True(t, ok)
				assert.IsType(t, defaultExecutionCondition{}, un.c)

				require.Len(t, rul.eh, 2)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks3.MechanismFactoryMock) { t.Helper() })

			handlerFactory := mocks3.NewMechanismFactoryMock(t)
			configureMocks(t, handlerFactory)

			factory := &ruleFactory{
				hf:             handlerFactory,
				defaultRule:    tc.defaultRule,
				mode:           tc.opMode,
				logger:         log.Logger,
				hasDefaultRule: x.IfThenElse(tc.defaultRule != nil, true, false),
			}

			// WHEN
			rul, err := factory.CreateRule("test", "test", tc.config)

			// THEN
			var (
				impl *ruleImpl
				ok   bool
			)

			if err == nil {
				impl, ok = rul.(*ruleImpl)
				require.True(t, ok)
			}

			// THEN
			tc.assert(t, err, impl)
		})
	}
}

func TestRuleFactoryConfigExtraction(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config any
		assert func(t *testing.T, conf map[string]any)
	}{
		"nil config": {
			assert: func(t *testing.T, conf map[string]any) {
				t.Helper()

				require.Nil(t, conf)
			},
		},
		"map[string]any": {
			config: map[string]any{"foo": "bar", "baz": []string{"zab"}},
			assert: func(t *testing.T, conf map[string]any) {
				t.Helper()

				require.NotEmpty(t, conf)
				assert.Equal(t, "bar", conf["foo"])
				assert.Equal(t, []string{"zab"}, conf["baz"])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			conf := getConfig(tc.config)

			// THEN
			tc.assert(t, conf)
		})
	}
}

func TestRuleFactoryStepIDExtraction(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		stepID any
		assert func(t *testing.T, value string)
	}{
		"nil value": {
			assert: func(t *testing.T, value string) {
				t.Helper()

				require.NotNil(t, value)
				require.Empty(t, value)
			},
		},
		"string": {
			stepID: "foo",
			assert: func(t *testing.T, value string) {
				t.Helper()

				require.Equal(t, "foo", value)
			},
		},
		"int": {
			stepID: 1,
			assert: func(t *testing.T, value string) {
				t.Helper()

				require.Equal(t, "1", value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			conf := getStepID(tc.stepID)

			// THEN
			tc.assert(t, conf)
		})
	}
}
