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
	"net/http"
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
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestRuleFactoryNew(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		config         *config.Configuration
		configureMocks func(t *testing.T, mhf *mocks3.FactoryMock)
		assert         func(t *testing.T, err error, ruleFactory *ruleFactory)
	}{
		{
			uc:     "new factory without default rule",
			config: &config.Configuration{},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ruleFactory)
				assert.Nil(t, ruleFactory.DefaultRule())
			},
		},
		{
			uc: "new factory with default rule with unsupported object in execute definition",
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
		{
			uc: "new factory with default rule with unsupported object in error handler definition",
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
		{
			uc: "new factory with malformed default rule, where authenticator loading happens after subject handlers",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"contextualizer": "bar"},
						{"authenticator": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateContextualizer(mock.Anything, "bar", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "an authenticator")
			},
		},
		{
			uc: "new factory with malformed default rule, where authenticator loading happens after finalizers",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar"},
						{"authenticator": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "an authenticator")
			},
		},
		{
			uc: "new factory with default rule, where authenticator loading results in an error",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authenticator": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with malformed default rule, where authorizer loading happens after finalizers",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar"},
						{"authorizer": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "before an authorizer")
			},
		},
		{
			uc: "new factory with default rule, where authorizer loading results in an error",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authorizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthorizer(mock.Anything, "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with malformed default rule, where contextualizer loading happens after finalizers",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar"},
						{"contextualizer": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "before a contextualizer")
			},
		},
		{
			uc: "new factory with default rule, where contextualizer loading results in an error",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"contextualizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateContextualizer(mock.Anything, "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with default rule, where finalizer loading results in an error",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"finalizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateFinalizer(mock.Anything, "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with default rule, where error_handler loading results in an error",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					ErrorHandler: []config.MechanismConfig{{"error_handler": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateErrorHandler(mock.Anything, "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with empty default rule",
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
		{
			uc: "new factory with default rule, consisting of authenticator only",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer and contextualizer",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"contextualizer": "baz"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateContextualizer(mock.Anything, "baz", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer, contextualizer and authorizer",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"contextualizer": "baz"},
						{"authorizer": "zab"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateContextualizer(mock.Anything, "baz", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
				mhf.EXPECT().CreateAuthorizer(mock.Anything, "zab", mock.Anything).
					Return(mocks4.NewAuthorizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer and finalizer with error while expanding methods",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"finalizer": "baz"},
					},
					Methods: []string{"FOO", ""},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateFinalizer(mock.Anything, "baz", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to expand")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer and finalizer without methods defined",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"finalizer": "baz"},
					},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateFinalizer(mock.Anything, "baz", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods defined")
			},
		},
		{
			uc: "new factory with default rule, configured with all required elements",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
					},
					Methods: []string{"FOO"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
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
				assert.Equal(t, config2.EncodedSlashesOff, defRule.encodedSlashesHandling)
				assert.ElementsMatch(t, defRule.methods, []string{"FOO"})
				assert.Len(t, defRule.sc, 1)
				assert.Empty(t, defRule.sh)
				assert.Empty(t, defRule.fi)
				assert.Empty(t, defRule.eh)
			},
		},
		{
			uc: "new factory with default rule, configured with all possible elements",
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"contextualizer": "foo"},
						{"authorizer": "zab"},
						{"finalizer": "baz"},
					},
					ErrorHandler: []config.MechanismConfig{
						{"error_handler": "foobar"},
						{"error_handler": "barfoo"},
					},
					Methods: []string{"FOO", "BAR"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator(mock.Anything, "bar", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateFinalizer(mock.Anything, "baz", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
				mhf.EXPECT().CreateAuthorizer(mock.Anything, "zab", mock.Anything).
					Return(mocks4.NewAuthorizerMock(t), nil)
				mhf.EXPECT().CreateContextualizer(mock.Anything, "foo", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
				mhf.EXPECT().CreateErrorHandler(mock.Anything, "foobar", mock.Anything).
					Return(mocks6.NewErrorHandlerMock(t), nil)
				mhf.EXPECT().CreateErrorHandler(mock.Anything, "barfoo", mock.Anything).
					Return(mocks6.NewErrorHandlerMock(t), nil)
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
				assert.Equal(t, config2.EncodedSlashesOff, defRule.encodedSlashesHandling)
				assert.ElementsMatch(t, defRule.methods, []string{"FOO", "BAR"})
				assert.Len(t, defRule.sc, 1)
				assert.Len(t, defRule.sh, 2)
				assert.Len(t, defRule.fi, 1)
				assert.Len(t, defRule.eh, 2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks3.FactoryMock) { t.Helper() })

			handlerFactory := mocks3.NewFactoryMock(t)
			configureMocks(t, handlerFactory)

			// WHEN
			factory, err := NewRuleFactory(handlerFactory, tc.config, config.DecisionMode, log.Logger)

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

	for _, tc := range []struct {
		uc             string
		opMode         config.OperationMode
		config         config2.Rule
		defaultRule    *ruleImpl
		configureMocks func(t *testing.T, mhf *mocks3.FactoryMock)
		assert         func(t *testing.T, err error, rul *ruleImpl)
	}{
		{
			uc:     "without default rule and with missing id",
			config: config2.Rule{},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no ID defined")
			},
		},
		{
			uc:     "in proxy mode, with id, but missing forward_to definition",
			opMode: config.ProxyMode,
			config: config2.Rule{ID: "foobar"},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no forward_to")
			},
		},
		{
			uc:     "in proxy mode, with id and empty forward_to definition",
			opMode: config.ProxyMode,
			config: config2.Rule{ID: "foobar", Backend: &config2.Backend{}},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "missing host")
			},
		},
		{
			uc:     "in proxy mode, with id and forward_to.host, but empty rewrite definition",
			opMode: config.ProxyMode,
			config: config2.Rule{
				ID: "foobar",
				Backend: &config2.Backend{
					Host:        "foo.bar",
					URLRewriter: &config2.URLRewriter{},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "rewrite is defined")
			},
		},
		{
			uc:     "without default rule, with id, but without url",
			config: config2.Rule{ID: "foobar"},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "bad URL pattern")
			},
		},
		{
			uc:     "without default rule, with id, but bad url pattern",
			config: config2.Rule{ID: "foobar", RuleMatcher: config2.Matcher{URL: "?>?<*??"}},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "bad URL pattern")
			},
		},
		{
			uc: "with error while creating execute pipeline",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "regex"},
				Execute:     []config.MechanismConfig{{"authenticator": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "with error while creating on_error pipeline",
			config: config2.Rule{
				ID:           "foobar",
				RuleMatcher:  config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				ErrorHandler: []config.MechanismConfig{{"error_handler": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateErrorHandler("test", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "without default rule and without any execute configuration",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "regex"},
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no authenticator defined")
			},
		},
		{
			uc: "without default rule and with only authenticator configured",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute:     []config.MechanismConfig{{"authenticator": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods defined")
			},
		},
		{
			uc: "without default rule and with only authenticator and contextualizer configured",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"contextualizer": "bar"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateContextualizer("test", "bar", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods defined")
			},
		},
		{
			uc: "without default rule and with only authenticator, contextualizer and authorizer configured",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "regex"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"contextualizer": "bar"},
					{"authorizer": "baz"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateContextualizer("test", "bar", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
				mhf.EXPECT().CreateAuthorizer("test", "baz", mock.Anything).
					Return(mocks4.NewAuthorizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods defined")
			},
		},
		{
			uc: "without default rule and with authenticator and finalizer configured, but with error while expanding methods",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"finalizer": "bar"},
				},
				Methods: []string{"FOO", ""},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed to expand")
			},
		},
		{
			uc: "without default rule and with authenticator and finalizer configured, but without methods",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"finalizer": "bar"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "no methods defined")
			},
		},
		{
			uc: "without default rule but with minimum required configuration in decision mode",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
				},
				Methods: []string{"FOO", "BAR"},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesOff, rul.encodedSlashesHandling)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"FOO", "BAR"})
				assert.Len(t, rul.sc, 1)
				assert.Empty(t, rul.sh)
				assert.Empty(t, rul.fi)
				assert.Empty(t, rul.eh)
			},
		},
		{
			uc:     "without default rule but with minimum required configuration in proxy mode",
			opMode: config.ProxyMode,
			config: config2.Rule{
				ID:          "foobar",
				Backend:     &config2.Backend{Host: "foo.bar"},
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
				},
				Methods: []string{"FOO", "BAR"},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesOff, rul.encodedSlashesHandling)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"FOO", "BAR"})
				assert.Len(t, rul.sc, 1)
				assert.Empty(t, rul.sh)
				assert.Empty(t, rul.fi)
				assert.Empty(t, rul.eh)
				assert.NotNil(t, rul.backend)
			},
		},
		{
			uc: "with default rule and with id and url only",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
			},
			defaultRule: &ruleImpl{
				methods: []string{"FOO"},
				sc:      compositeSubjectCreator{&mocks.SubjectHandlerMock{}},
				sh:      compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				fi:      compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				eh:      compositeErrorHandler{&mocks.ErrorHandlerMock{}},
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"FOO"})
				assert.Len(t, rul.sc, 1)
				assert.Len(t, rul.sh, 1)
				assert.Len(t, rul.fi, 1)
				assert.Len(t, rul.eh, 1)
			},
		},
		{
			uc: "with default rule and with all attributes defined by the rule itself in decision mode",
			config: config2.Rule{
				ID:                     "foobar",
				RuleMatcher:            config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				EncodedSlashesHandling: config2.EncodedSlashesNoDecode,
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"contextualizer": "bar"},
					{"authorizer": "zab"},
					{"finalizer": "baz"},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo"},
				},
				Methods: []string{"BAR", "BAZ"},
			},
			defaultRule: &ruleImpl{
				methods: []string{"FOO"},
				sc:      compositeSubjectCreator{&mocks.SubjectHandlerMock{}},
				sh:      compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				fi:      compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				eh:      compositeErrorHandler{&mocks.ErrorHandlerMock{}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateContextualizer("test", "bar", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
				mhf.EXPECT().CreateAuthorizer("test", "zab", mock.Anything).
					Return(mocks4.NewAuthorizerMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "baz", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
				mhf.EXPECT().CreateErrorHandler("test", "foo", mock.Anything).
					Return(mocks6.NewErrorHandlerMock(t), nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesNoDecode, rul.encodedSlashesHandling)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"BAR", "BAZ"})

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
		{
			uc:     "with default rule and with all attributes defined by the rule itself in proxy mode",
			opMode: config.ProxyMode,
			config: config2.Rule{
				ID:                     "foobar",
				RuleMatcher:            config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
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
					{"authenticator": "foo"},
					{"contextualizer": "bar"},
					{"authorizer": "zab"},
					{"finalizer": "baz"},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo"},
				},
				Methods: []string{"BAR", "BAZ"},
			},
			defaultRule: &ruleImpl{
				methods: []string{"FOO"},
				sc:      compositeSubjectCreator{&mocks.SubjectHandlerMock{}},
				sh:      compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				fi:      compositeSubjectHandler{&mocks.SubjectHandlerMock{}},
				eh:      compositeErrorHandler{&mocks.ErrorHandlerMock{}},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateContextualizer("test", "bar", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
				mhf.EXPECT().CreateAuthorizer("test", "zab", mock.Anything).
					Return(mocks4.NewAuthorizerMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "baz", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
				mhf.EXPECT().CreateErrorHandler("test", "foo", mock.Anything).
					Return(mocks6.NewErrorHandlerMock(t), nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, config2.EncodedSlashesOn, rul.encodedSlashesHandling)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"BAR", "BAZ"})
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
		{
			uc: "with conditional execution configuration type error",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"finalizer": "bar", "if": 1},
				},
				Methods: []string{"FOO"},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "unexpected type")
			},
		},
		{
			uc: "with empty conditional execution configuration",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"finalizer": "bar", "if": ""},
				},
				Methods: []string{"FOO"},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "empty execution condition")
			},
		},
		{
			uc: "with conditional execution for some mechanisms",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"authorizer": "bar", "if": "false"},
					{"contextualizer": "bar", "if": "true"},
					{"authorizer": "baz"},
					{"finalizer": "bar", "if": "true"},
				},
				Methods: []string{"FOO"},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateAuthorizer("test", mock.Anything, mock.Anything).
					Return(mocks4.NewAuthorizerMock(t), nil).Times(2)
				mhf.EXPECT().CreateContextualizer("test", "bar", mock.Anything).
					Return(mocks5.NewContextualizerMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "bar", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"FOO"})

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
		{
			uc: "with conditional execution for error handler",
			config: config2.Rule{
				ID:          "foobar",
				RuleMatcher: config2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"authorizer": "bar"},
					{"finalizer": "baz"},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo", "if": "true", "config": map[string]any{}},
					{"error_handler": "bar", "if": "false", "config": map[string]any{}},
				},
				Methods: []string{"FOO"},
			},
			configureMocks: func(t *testing.T, mhf *mocks3.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateAuthenticator("test", "foo", mock.Anything).
					Return(mocks2.NewAuthenticatorMock(t), nil)
				mhf.EXPECT().CreateAuthorizer("test", "bar", mock.Anything).
					Return(mocks4.NewAuthorizerMock(t), nil)
				mhf.EXPECT().CreateFinalizer("test", "baz", mock.Anything).
					Return(mocks7.NewFinalizerMock(t), nil)
				mhf.EXPECT().CreateErrorHandler("test", "foo",
					mock.MatchedBy(func(conf map[string]any) bool { return conf["if"] == "true" }),
				).Return(mocks6.NewErrorHandlerMock(t), nil)
				mhf.EXPECT().CreateErrorHandler("test", "bar",
					mock.MatchedBy(func(conf map[string]any) bool { return conf["if"] == "false" }),
				).Return(mocks6.NewErrorHandlerMock(t), nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"FOO"})

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
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks3.FactoryMock) { t.Helper() })

			handlerFactory := mocks3.NewFactoryMock(t)
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

	for _, tc := range []struct {
		uc     string
		config any
		assert func(t *testing.T, conf map[string]any)
	}{
		{
			uc: "nil config",
			assert: func(t *testing.T, conf map[string]any) {
				t.Helper()

				require.Nil(t, conf)
			},
		},
		{
			uc:     "map[string]any",
			config: map[string]any{"foo": "bar", "baz": []string{"zab"}},
			assert: func(t *testing.T, conf map[string]any) {
				t.Helper()

				require.NotEmpty(t, conf)
				assert.Equal(t, "bar", conf["foo"])
				assert.Equal(t, []string{"zab"}, conf["baz"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// WHEN
			conf := getConfig(tc.config)

			// THEN
			tc.assert(t, conf)
		})
	}
}

func TestRuleFactoryProxyModeApplicability(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		ruleConfig  config2.Rule
		shouldError bool
	}{
		{
			uc:          "no upstream url factory",
			ruleConfig:  config2.Rule{},
			shouldError: true,
		},
		{
			uc:          "no host defined",
			ruleConfig:  config2.Rule{Backend: &config2.Backend{}},
			shouldError: true,
		},
		{
			uc:         "with host but no rewrite options",
			ruleConfig: config2.Rule{Backend: &config2.Backend{Host: "foo.bar"}},
		},
		{
			uc: "with host and empty rewrite option",
			ruleConfig: config2.Rule{
				Backend: &config2.Backend{
					Host:        "foo.bar",
					URLRewriter: &config2.URLRewriter{},
				},
			},
			shouldError: true,
		},
		{
			uc: "with host and scheme rewrite option",
			ruleConfig: config2.Rule{
				Backend: &config2.Backend{
					Host:        "foo.bar",
					URLRewriter: &config2.URLRewriter{Scheme: "https"},
				},
			},
		},
		{
			uc: "with host and strip path prefix rewrite option",
			ruleConfig: config2.Rule{
				Backend: &config2.Backend{
					Host:        "foo.bar",
					URLRewriter: &config2.URLRewriter{PathPrefixToCut: "/foo"},
				},
			},
		},
		{
			uc: "with host and add path prefix rewrite option",
			ruleConfig: config2.Rule{
				Backend: &config2.Backend{
					Host:        "foo.bar",
					URLRewriter: &config2.URLRewriter{PathPrefixToAdd: "/foo"},
				},
			},
		},
		{
			uc: "with host and empty strip query parameter rewrite option",
			ruleConfig: config2.Rule{
				Backend: &config2.Backend{
					Host:        "foo.bar",
					URLRewriter: &config2.URLRewriter{QueryParamsToRemove: []string{}},
				},
			},
			shouldError: true,
		},
		{
			uc: "with host and strip query parameter rewrite option",
			ruleConfig: config2.Rule{
				Backend: &config2.Backend{
					Host:        "foo.bar",
					URLRewriter: &config2.URLRewriter{QueryParamsToRemove: []string{"foo"}},
				},
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			err := checkProxyModeApplicability("test", tc.ruleConfig)

			// THEN
			if tc.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExpandHTTPMethods(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		configured  []string
		expected    []string
		shouldError bool
	}{
		{
			uc: "empty configuration",
		},
		{
			uc:          "empty method in list",
			configured:  []string{"FOO", ""},
			shouldError: true,
		},
		{
			uc:         "duplicates should be removed",
			configured: []string{"BAR", "BAZ", "BAZ", "FOO", "FOO", "ZAB"},
			expected:   []string{"BAR", "BAZ", "FOO", "ZAB"},
		},
		{
			uc:         "only ALL configured",
			configured: []string{"ALL"},
			expected: []string{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions,
				http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace,
			},
		},
		{
			uc:         "ALL without POST and TRACE",
			configured: []string{"ALL", "!POST", "!TRACE"},
			expected: []string{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
				http.MethodOptions, http.MethodPatch, http.MethodPut,
			},
		},
		{
			uc:         "ALL with duplicates and without POST and TRACE",
			configured: []string{"ALL", "GET", "!POST", "!TRACE", "!TRACE"},
			expected: []string{
				http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
				http.MethodOptions, http.MethodPatch, http.MethodPut,
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// WHEN
			res, err := expandHTTPMethods(tc.configured)

			// THEN
			if tc.shouldError {
				require.Error(t, err)
			} else {
				require.Equal(t, tc.expected, res)
			}
		})
	}
}
