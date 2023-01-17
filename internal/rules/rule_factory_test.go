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
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks3 "github.com/dadrus/heimdall/internal/rules/mechanisms/mocks"
	"github.com/dadrus/heimdall/internal/rules/mocks"
	event2 "github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

// nolint: maintidx
func TestRuleFactoryNew(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		config         *config.Configuration
		configureMocks func(t *testing.T, mhf *mocks.MockFactory)
		assert         func(t *testing.T, err error, ruleFactory *ruleFactory)
	}{
		{
			uc:     "new factory without default rule",
			config: &config.Configuration{Rules: config.Rules{}},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ruleFactory)
				assert.False(t, ruleFactory.HasDefaultRule())
				assert.Nil(t, ruleFactory.DefaultRule())
			},
		},
		{
			uc: "new factory with default rule with unsupported object in execute definition",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"foo": "bar"},
					},
				},
			}},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "unsupported configuration")
			},
		},
		{
			uc: "new factory with default rule with unsupported object in error handler definition",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					ErrorHandler: []config.MechanismConfig{
						{"foo": "bar"},
					},
				},
			}},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "unsupported configuration")
			},
		},
		{
			uc: "new factory with malformed default rule, where authenticator loading happens after subject handlers",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"contextualizer": "bar"},
						{"authenticator": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateContextualizer", "bar", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "an authenticator")
			},
		},
		{
			uc: "new factory with malformed default rule, where authenticator loading happens after unifier handlers",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"unifier": "bar"},
						{"authenticator": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateUnifier", "bar", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "an authenticator")
			},
		},
		{
			uc: "new factory with default rule, where authenticator loading results in an error",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authenticator": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with malformed default rule, where authorizer loading happens after unifier handlers",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"unifier": "bar"},
						{"authorizer": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateUnifier", "bar", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "before an authorizer")
			},
		},
		{
			uc: "new factory with default rule, where authorizer loading results in an error",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authorizer": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthorizer", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with malformed default rule, where contextualizer loading happens after unifier handlers",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"unifier": "bar"},
						{"contextualizer": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateUnifier", "bar", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "before a contextualizer")
			},
		},
		{
			uc: "new factory with default rule, where contextualizer loading results in an error",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"contextualizer": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateContextualizer", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with default rule, where unifier loading results in an error",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"unifier": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateUnifier", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with default rule, where error_handler loading results in an error",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					ErrorHandler: []config.MechanismConfig{{"error_handler": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateErrorHandler", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with empty default rule",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{},
				},
			}},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no authenticator")
			},
		},
		{
			uc: "new factory with default rule, consisting of authenticator only",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no unifier")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer and contextualizer",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"contextualizer": "baz"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateContextualizer", "baz", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no unifier")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer, contextualizer and authorizer",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"contextualizer": "baz"},
						{"authorizer": "zab"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateContextualizer", "baz", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateAuthorizer", "zab", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no unifier")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer and unifier without methods defined",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"unifier": "baz"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateUnifier", "baz", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no methods defined")
			},
		},
		{
			uc: "new factory with default rule, configured with all required elements",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"unifier": "baz"},
					},
					Methods: []string{"FOO"},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateUnifier", "baz", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleFactory)
				assert.True(t, ruleFactory.HasDefaultRule())
				assert.NotNil(t, ruleFactory.DefaultRule())
				assert.Equal(t, ruleFactory.defaultRule, ruleFactory.DefaultRule())

				defRule := ruleFactory.defaultRule
				assert.True(t, defRule.isDefault)
				assert.Equal(t, "default", defRule.id)
				assert.Equal(t, "config", defRule.srcID)
				assert.ElementsMatch(t, defRule.methods, []string{"FOO"})
				assert.Len(t, defRule.sc, 1)
				assert.Len(t, defRule.sh, 0)
				assert.Len(t, defRule.un, 1)
				assert.Len(t, defRule.eh, 0)
			},
		},
		{
			uc: "new factory with default rule, configured with all possible elements",
			config: &config.Configuration{Rules: config.Rules{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
						{"contextualizer": "foo"},
						{"authorizer": "zab"},
						{"unifier": "baz"},
					},
					ErrorHandler: []config.MechanismConfig{
						{"error_handler": "foobar"},
						{"error_handler": "barfoo"},
					},
					Methods: []string{"FOO", "BAR"},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateUnifier", "baz", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateAuthorizer", "zab", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateContextualizer", "foo", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateErrorHandler", "foobar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateErrorHandler", "barfoo", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleFactory)
				assert.True(t, ruleFactory.HasDefaultRule())
				assert.NotNil(t, ruleFactory.DefaultRule())
				assert.Equal(t, ruleFactory.defaultRule, ruleFactory.DefaultRule())

				defRule := ruleFactory.defaultRule
				assert.True(t, defRule.isDefault)
				assert.Equal(t, "default", defRule.id)
				assert.Equal(t, "config", defRule.srcID)
				assert.ElementsMatch(t, defRule.methods, []string{"FOO", "BAR"})
				assert.Len(t, defRule.sc, 1)
				assert.Len(t, defRule.sh, 2)
				assert.Len(t, defRule.un, 1)
				assert.Len(t, defRule.eh, 2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, mhf *mocks.MockFactory) { t.Helper() })

			handlerFactory := &mocks.MockFactory{}
			configureMocks(t, handlerFactory)

			// WHEN
			factory, err := NewRuleFactory(handlerFactory, tc.config, log.Logger)

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
			handlerFactory.AssertExpectations(t)
		})
	}
}

// nolint: maintidx
func TestRuleFactoryCreateRule(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		config         event2.RuleConfiguration
		defaultRule    *ruleImpl
		configureMocks func(t *testing.T, mhf *mocks.MockFactory)
		assert         func(t *testing.T, err error, rul *ruleImpl)
	}{
		{
			uc:     "without default rule and with missing id",
			config: event2.RuleConfiguration{},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no ID defined")
			},
		},
		{
			uc:     "without default rule, with id, but without url",
			config: event2.RuleConfiguration{ID: "foobar"},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no URL defined")
			},
		},
		{
			uc:     "without default rule, with id, but bad url pattern",
			config: event2.RuleConfiguration{ID: "foobar", RuleMatcher: event2.Matcher{URL: "?>?<*??"}},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "bad URL pattern")
			},
		},
		{
			uc: "without default rule and error in upstream url",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Upstream:    "http://[::1]:namedport",
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "bad upstream URL")
			},
		},
		{
			uc: "with error while creating execute pipeline",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "regex"},
				Execute:     []config.MechanismConfig{{"authenticator": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "with error while creating on_error pipeline",
			config: event2.RuleConfiguration{
				ID:           "foobar",
				RuleMatcher:  event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				ErrorHandler: []config.MechanismConfig{{"error_handler": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateErrorHandler", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "without default rule and without any execute configuration",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "regex"},
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no authenticator defined")
			},
		},
		{
			uc: "without default rule and with only authenticator configured",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute:     []config.MechanismConfig{{"authenticator": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks3.MockAuthenticator{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no unifier defined")
			},
		},
		{
			uc: "without default rule and with only authenticator and contextualizer configured",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"contextualizer": "bar"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks3.MockAuthenticator{}, nil)
				mhf.On("CreateContextualizer", "bar", mock.Anything).
					Return(&mocks3.MockContextualizer{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no unifier defined")
			},
		},
		{
			uc: "without default rule and with only authenticator, contextualizer and authorizer configured",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "regex"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"contextualizer": "bar"},
					{"authorizer": "baz"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks3.MockAuthenticator{}, nil)
				mhf.On("CreateContextualizer", "bar", mock.Anything).
					Return(&mocks3.MockContextualizer{}, nil)
				mhf.On("CreateAuthorizer", "baz", mock.Anything).
					Return(&mocks3.MockAuthorizer{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no unifier defined")
			},
		},
		{
			uc: "without default rule and with authenticator and unifier configured, but without methods",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"unifier": "bar"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks3.MockAuthenticator{}, nil)
				mhf.On("CreateUnifier", "bar", mock.Anything).
					Return(&mocks3.MockUnifier{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no methods defined")
			},
		},
		{
			uc: "without default rule but with minimum required configuration",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"unifier": "bar"},
				},
				Methods: []string{"FOO", "BAR"},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks3.MockAuthenticator{}, nil)
				mhf.On("CreateUnifier", "bar", mock.Anything).
					Return(&mocks3.MockUnifier{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"FOO", "BAR"})
				assert.Len(t, rul.sc, 1)
				assert.Len(t, rul.sh, 0)
				assert.Len(t, rul.un, 1)
				assert.Len(t, rul.eh, 0)
			},
		},
		{
			uc: "with default rule and with id and url only",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
			},
			defaultRule: &ruleImpl{
				methods: []string{"FOO"},
				sc:      compositeSubjectCreator{&mocks.MockSubjectCreator{}},
				sh:      compositeSubjectHandler{&mocks.MockSubjectHandler{}},
				un:      compositeSubjectHandler{&mocks.MockSubjectHandler{}},
				eh:      compositeErrorHandler{&mocks.MockErrorHandler{}},
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
				assert.Len(t, rul.un, 1)
				assert.Len(t, rul.eh, 1)
			},
		},
		{
			uc: "with default rule and with all attributes defined by the rule itself",
			config: event2.RuleConfiguration{
				ID:          "foobar",
				RuleMatcher: event2.Matcher{URL: "http://foo.bar", Strategy: "glob"},
				Upstream:    "http://bar.foo",
				Execute: []config.MechanismConfig{
					{"authenticator": "foo"},
					{"contextualizer": "bar"},
					{"authorizer": "zab"},
					{"unifier": "baz"},
				},
				ErrorHandler: []config.MechanismConfig{
					{"error_handler": "foo"},
				},
				Methods: []string{"BAR", "BAZ"},
			},
			defaultRule: &ruleImpl{
				methods: []string{"FOO"},
				sc:      compositeSubjectCreator{&mocks.MockSubjectCreator{}},
				sh:      compositeSubjectHandler{&mocks.MockSubjectHandler{}},
				un:      compositeSubjectHandler{&mocks.MockSubjectHandler{}},
				eh:      compositeErrorHandler{&mocks.MockErrorHandler{}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks3.MockAuthenticator{}, nil)
				mhf.On("CreateContextualizer", "bar", mock.Anything).
					Return(&mocks3.MockContextualizer{}, nil)
				mhf.On("CreateAuthorizer", "zab", mock.Anything).
					Return(&mocks3.MockAuthorizer{}, nil)
				mhf.On("CreateUnifier", "baz", mock.Anything).
					Return(&mocks3.MockUnifier{}, nil)
				mhf.On("CreateErrorHandler", "foo", mock.Anything).
					Return(&mocks3.MockErrorHandler{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.NotNil(t, rul.urlMatcher)
				assert.ElementsMatch(t, rul.methods, []string{"BAR", "BAZ"})
				assert.Equal(t, "http://bar.foo", rul.upstreamURL.String())

				// nil checks above mean the responses from the mockHandlerFactory are used
				// and not the values from the default rule
				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])
				require.Len(t, rul.sh, 2)
				assert.NotNil(t, rul.sh[0])
				assert.NotNil(t, rul.sh[1])
				require.Len(t, rul.un, 1)
				assert.NotNil(t, rul.un[0])
				require.Len(t, rul.eh, 1)
				assert.NotNil(t, rul.eh[0])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, mhf *mocks.MockFactory) { t.Helper() })

			handlerFactory := &mocks.MockFactory{}
			configureMocks(t, handlerFactory)

			factory := &ruleFactory{
				hf:             handlerFactory,
				defaultRule:    tc.defaultRule,
				logger:         log.Logger,
				hasDefaultRule: x.IfThenElse(tc.defaultRule != nil, true, false),
			}

			// WHEN
			rul, err := factory.CreateRule("test", tc.config)

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
			handlerFactory.AssertExpectations(t)
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
			// GIVEN
			factory := &ruleFactory{logger: log.Logger}

			// WHEN
			conf := factory.getConfig(tc.config)

			// THEN
			tc.assert(t, conf)
		})
	}
}
