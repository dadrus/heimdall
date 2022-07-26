package rules

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	mocks2 "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

// nolint: maintidx
func TestRuleFactoryNew(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		config         config.Configuration
		configureMocks func(t *testing.T, mhf *mocks.MockHandlerFactory)
		assert         func(t *testing.T, err error, ruleFactory *ruleFactory)
	}{
		{
			uc:     "new factory without default rule",
			config: config.Configuration{Rules: config.RulesConfig{}},
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					ErrorHandler: []map[string]any{
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"hydrator": "bar"},
						{"authenticator": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateHydrator", "bar", mock.Anything).
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
			uc: "new factory with malformed default rule, where authenticator loading happens after mutator handlers",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"mutator": "bar"},
						{"authenticator": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateMutator", "bar", mock.Anything).
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{{"authenticator": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
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
			uc: "new factory with malformed default rule, where authorizer loading happens after mutator handlers",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"mutator": "bar"},
						{"authorizer": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateMutator", "bar", mock.Anything).
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{{"authorizer": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
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
			uc: "new factory with malformed default rule, where hydrator loading happens after mutator handlers",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"mutator": "bar"},
						{"hydrator": "foo"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateMutator", "bar", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "before a hydrator")
			},
		},
		{
			uc: "new factory with default rule, where hydrator loading results in an error",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{{"hydrator": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateHydrator", "foo", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.Equal(t, testsupport.ErrTestPurpose, err)
			},
		},
		{
			uc: "new factory with default rule, where mutator loading results in an error",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{{"mutator": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateMutator", "foo", mock.Anything).
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					ErrorHandler: []map[string]any{{"error_handler": "foo"}},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{},
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"authenticator": "bar"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no mutator")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer and hydrator",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"authenticator": "bar"},
						{"hydrator": "baz"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateHydrator", "baz", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no mutator")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer, hydrator and authorizer",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"authenticator": "bar"},
						{"hydrator": "baz"},
						{"authorizer": "zab"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateHydrator", "baz", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateAuthorizer", "zab", mock.Anything).
					Return(nil, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no mutator")
			},
		},
		{
			uc: "new factory with default rule, consisting of authorizer and mutator without methods defined",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"authenticator": "bar"},
						{"mutator": "baz"},
					},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateMutator", "baz", mock.Anything).
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
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"authenticator": "bar"},
						{"mutator": "baz"},
					},
					Methods: []string{"FOO"},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateMutator", "baz", mock.Anything).
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
				assert.Len(t, defRule.m, 1)
				assert.Len(t, defRule.eh, 0)
			},
		},
		{
			uc: "new factory with default rule, configured with all possible elements",
			config: config.Configuration{Rules: config.RulesConfig{
				Default: &config.DefaultRuleConfig{
					Execute: []map[string]any{
						{"authenticator": "bar"},
						{"hydrator": "foo"},
						{"authorizer": "zab"},
						{"mutator": "baz"},
					},
					ErrorHandler: []map[string]any{
						{"error_handler": "foobar"},
						{"error_handler": "barfoo"},
					},
					Methods: []string{"FOO", "BAR"},
				},
			}},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "bar", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateMutator", "baz", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateAuthorizer", "zab", mock.Anything).
					Return(nil, nil)
				mhf.On("CreateHydrator", "foo", mock.Anything).
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
				assert.Len(t, defRule.m, 1)
				assert.Len(t, defRule.eh, 2)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, mhf *mocks.MockHandlerFactory) { t.Helper() })

			handlerFactory := &mocks.MockHandlerFactory{}
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
		config         config.RuleConfig
		defaultRule    *ruleImpl
		configureMocks func(t *testing.T, mhf *mocks.MockHandlerFactory)
		assert         func(t *testing.T, err error, rul *ruleImpl)
	}{
		{
			uc:     "without default rule and with missing id",
			config: config.RuleConfig{},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no ID defined")
			},
		},
		{
			uc:     "without default rule, with id, but without url",
			config: config.RuleConfig{ID: "foobar"},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no URL defined")
			},
		},
		{
			uc:     "without default rule, with id, but bad url pattern",
			config: config.RuleConfig{ID: "foobar", URL: "?>?<*??"},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "bad URL pattern")
			},
		},
		{
			uc:     "without default rule and error in upstream url",
			config: config.RuleConfig{ID: "foobar", URL: "http://foo.bar", Upstream: "http://[::1]:namedport"},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "bad upstream URL")
			},
		},
		{
			uc: "with error while creating execute pipeline",
			config: config.RuleConfig{
				ID:      "foobar",
				URL:     "http://foo.bar",
				Execute: []map[string]any{{"authenticator": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
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
			config: config.RuleConfig{
				ID:           "foobar",
				URL:          "http://foo.bar",
				ErrorHandler: []map[string]any{{"error_handler": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
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
			config: config.RuleConfig{
				ID:  "foobar",
				URL: "http://foo.bar",
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
			config: config.RuleConfig{
				ID:      "foobar",
				URL:     "http://foo.bar",
				Execute: []map[string]any{{"authenticator": "foo"}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks2.MockAuthenticator{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no mutator defined")
			},
		},
		{
			uc: "without default rule and with only authenticator and hydrator configured",
			config: config.RuleConfig{
				ID:  "foobar",
				URL: "http://foo.bar",
				Execute: []map[string]any{
					{"authenticator": "foo"},
					{"hydrator": "bar"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks2.MockAuthenticator{}, nil)
				mhf.On("CreateHydrator", "bar", mock.Anything).
					Return(&mocks2.MockHydrator{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no mutator defined")
			},
		},
		{
			uc: "without default rule and with only authenticator, hydrator and authorizer configured",
			config: config.RuleConfig{
				ID:  "foobar",
				URL: "http://foo.bar",
				Execute: []map[string]any{
					{"authenticator": "foo"},
					{"hydrator": "bar"},
					{"authorizer": "baz"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks2.MockAuthenticator{}, nil)
				mhf.On("CreateHydrator", "bar", mock.Anything).
					Return(&mocks2.MockHydrator{}, nil)
				mhf.On("CreateAuthorizer", "baz", mock.Anything).
					Return(&mocks2.MockAuthorizer{}, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no mutator defined")
			},
		},
		{
			uc: "without default rule and with authenticator and mutator configured, but without methods",
			config: config.RuleConfig{
				ID:  "foobar",
				URL: "http://foo.bar",
				Execute: []map[string]any{
					{"authenticator": "foo"},
					{"mutator": "bar"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks2.MockAuthenticator{}, nil)
				mhf.On("CreateMutator", "bar", mock.Anything).
					Return(&mocks2.MockMutator{}, nil)
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
			config: config.RuleConfig{
				ID:  "foobar",
				URL: "http://foo.bar",
				Execute: []map[string]any{
					{"authenticator": "foo"},
					{"mutator": "bar"},
				},
				Methods: []string{"FOO", "BAR"},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks2.MockAuthenticator{}, nil)
				mhf.On("CreateMutator", "bar", mock.Anything).
					Return(&mocks2.MockMutator{}, nil)
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
				assert.Len(t, rul.m, 1)
				assert.Len(t, rul.eh, 0)
			},
		},
		{
			uc: "with default rule and with id and url only",
			config: config.RuleConfig{
				ID:  "foobar",
				URL: "http://foo.bar",
			},
			defaultRule: &ruleImpl{
				methods: []string{"FOO"},
				sc:      compositeSubjectCreator{&mocks.MockSubjectCreator{}},
				sh:      compositeSubjectHandler{&mocks.MockSubjectHandler{}},
				m:       compositeSubjectHandler{&mocks.MockSubjectHandler{}},
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
				assert.Len(t, rul.m, 1)
				assert.Len(t, rul.eh, 1)
			},
		},
		{
			uc: "with default rule and with all attributes defined by the rule itself",
			config: config.RuleConfig{
				ID:       "foobar",
				URL:      "http://foo.bar",
				Upstream: "http://bar.foo",
				Execute: []map[string]any{
					{"authenticator": "foo"},
					{"hydrator": "bar"},
					{"authorizer": "zab"},
					{"mutator": "baz"},
				},
				ErrorHandler: []map[string]any{
					{"error_handler": "foo"},
				},
				Methods: []string{"BAR", "BAZ"},
			},
			defaultRule: &ruleImpl{
				methods: []string{"FOO"},
				sc:      compositeSubjectCreator{&mocks.MockSubjectCreator{}},
				sh:      compositeSubjectHandler{&mocks.MockSubjectHandler{}},
				m:       compositeSubjectHandler{&mocks.MockSubjectHandler{}},
				eh:      compositeErrorHandler{&mocks.MockErrorHandler{}},
			},
			configureMocks: func(t *testing.T, mhf *mocks.MockHandlerFactory) {
				t.Helper()

				mhf.On("CreateAuthenticator", "foo", mock.Anything).
					Return(&mocks2.MockAuthenticator{}, nil)
				mhf.On("CreateHydrator", "bar", mock.Anything).
					Return(&mocks2.MockHydrator{}, nil)
				mhf.On("CreateAuthorizer", "zab", mock.Anything).
					Return(&mocks2.MockAuthorizer{}, nil)
				mhf.On("CreateMutator", "baz", mock.Anything).
					Return(&mocks2.MockMutator{}, nil)
				mhf.On("CreateErrorHandler", "foo", mock.Anything).
					Return(&mocks2.MockErrorHandler{}, nil)
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
				require.Len(t, rul.m, 1)
				assert.NotNil(t, rul.m[0])
				require.Len(t, rul.eh, 1)
				assert.NotNil(t, rul.eh[0])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, mhf *mocks.MockHandlerFactory) { t.Helper() })

			handlerFactory := &mocks.MockHandlerFactory{}
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
			uc:     "map[any]any",
			config: map[any]any{"foo": "bar", "baz": []string{"zab"}},
			assert: func(t *testing.T, conf map[string]any) {
				t.Helper()

				require.NotEmpty(t, conf)
				assert.Equal(t, "bar", conf["foo"])
				assert.Equal(t, []string{"zab"}, conf["baz"])
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
