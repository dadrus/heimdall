package rules

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestRepositoryAddAndRemoveRulesFromSameRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	r, err := NewRepository(nil, nil, *zerolog.Ctx(context.Background()))
	require.NoError(t, err)

	repo, ok := r.(*repository)
	require.True(t, ok)

	// WHEN
	repo.addRule(&ruleImpl{id: "1", srcID: "bar"})
	repo.addRule(&ruleImpl{id: "2", srcID: "bar"})
	repo.addRule(&ruleImpl{id: "3", srcID: "bar"})
	repo.addRule(&ruleImpl{id: "4", srcID: "bar"})

	// THEN
	assert.Len(t, repo.rules, 4)

	// WHEN
	repo.removeRules("bar")

	// THEN
	assert.Len(t, repo.rules, 0)
}

func TestRepositoryFindRule(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		requestURL     *url.URL
		addRules       func(t *testing.T, repo *repository)
		configureMocks func(t *testing.T, factory *mocks.MockRuleFactory)
		assert         func(t *testing.T, err error, rul rule.Rule)
	}{
		{
			uc:         "no matching rule without default rule",
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "baz"},
			configureMocks: func(t *testing.T, factory *mocks.MockRuleFactory) {
				t.Helper()

				factory.On("HasDefaultRule").Return(false)
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNoRuleFound)
			},
		},
		{
			uc:         "no matching rule with default rule",
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "baz"},
			configureMocks: func(t *testing.T, factory *mocks.MockRuleFactory) {
				t.Helper()

				factory.On("HasDefaultRule").Return(true)
				factory.On("DefaultRule").Return(&ruleImpl{id: "test", srcID: "baz"})
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, &ruleImpl{id: "test", srcID: "baz"}, rul)
			},
		},
		{
			uc:         "matching rule",
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "baz"},
			addRules: func(t *testing.T, repo *repository) {
				t.Helper()

				repo.rules = append(repo.rules,
					&ruleImpl{
						id:    "test1",
						srcID: "bar",
						urlMatcher: func() patternmatcher.PatternMatcher {
							matcher, _ := patternmatcher.NewPatternMatcher("glob",
								"http://heimdall.test.local/baz")

							return matcher
						}(),
					},
					&ruleImpl{
						id:    "test2",
						srcID: "baz",
						urlMatcher: func() patternmatcher.PatternMatcher {
							matcher, _ := patternmatcher.NewPatternMatcher("glob",
								"http://foo.bar/baz")

							return matcher
						}(),
					},
				)
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.NoError(t, err)

				impl, ok := rul.(*ruleImpl)
				require.True(t, ok)

				require.Equal(t, "test2", impl.id)
				require.Equal(t, "baz", impl.srcID)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks.MockRuleFactory) { t.Helper() })

			addRules := x.IfThenElse(tc.addRules != nil,
				tc.addRules,
				func(t *testing.T, _ *repository) { t.Helper() })

			factory := &mocks.MockRuleFactory{}
			configureMocks(t, factory)

			r, err := NewRepository(nil, factory, *zerolog.Ctx(context.Background()))
			require.NoError(t, err)

			repo, ok := r.(*repository)
			require.True(t, ok)

			addRules(t, repo)

			// WHEN
			rul, err := repo.FindRule(tc.requestURL)

			// THEN
			tc.assert(t, err, rul)
			factory.AssertExpectations(t)
		})
	}
}

func TestRepositoryAddAndRemoveRulesFromDifferentRuleSets(t *testing.T) {
	t.Parallel()

	// GIVEN
	r, err := NewRepository(nil, nil, *zerolog.Ctx(context.Background()))
	require.NoError(t, err)

	repo, ok := r.(*repository)
	require.True(t, ok)

	// WHEN
	repo.addRule(&ruleImpl{id: "1", srcID: "bar"})
	repo.addRule(&ruleImpl{id: "2", srcID: "baz"})
	repo.addRule(&ruleImpl{id: "3", srcID: "bar"})
	repo.addRule(&ruleImpl{id: "4", srcID: "foo"})

	// THEN
	assert.Len(t, repo.rules, 4)

	// WHEN
	repo.removeRules("baz")

	// THEN
	assert.Len(t, repo.rules, 3)
	assert.ElementsMatch(t, repo.rules, []rule.Rule{
		&ruleImpl{id: "1", srcID: "bar"},
		&ruleImpl{id: "3", srcID: "bar"},
		&ruleImpl{id: "4", srcID: "foo"},
	})

	// WHEN
	repo.removeRules("foo")

	// THEN
	assert.Len(t, repo.rules, 2)
	assert.ElementsMatch(t, repo.rules, []rule.Rule{
		&ruleImpl{id: "1", srcID: "bar"},
		&ruleImpl{id: "3", srcID: "bar"},
	})

	// WHEN
	repo.removeRules("bar")

	// THEN
	assert.Len(t, repo.rules, 0)
}

func TestRepositoryRuleSetLifecycleManagement(t *testing.T) {
	t.Parallel()

	queue := make(event.RuleSetChangedEventQueue, 10)
	defer close(queue)

	repo, err := NewRepository(queue, nil, log.Logger)
	require.NoError(t, err)

	impl, ok := repo.(*repository)
	require.True(t, ok)

	require.NoError(t, impl.Start())

	// nolint: errcheck
	defer impl.Stop()

	for _, tc := range []struct {
		uc             string
		events         []event.RuleSetChangedEvent
		configureMocks func(t *testing.T, factory *mocks.MockRuleFactory)
		assert         func(t *testing.T, repo *repository)
	}{
		{
			uc:     "empty rule set definition",
			events: []event.RuleSetChangedEvent{{Src: "test", ChangeType: event.Create}},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.rules, 0)
			},
		},
		{
			uc: "rule set with one rule",
			events: []event.RuleSetChangedEvent{
				{
					Src:        "test",
					ChangeType: event.Create,
					Definition: []byte(`
- id: rule:foo
  url: http://foo.bar/<**>
  methods:
   - PATCH
  matching_strategy: regex
  execute:
    - authenticator: unauthorized_authenticator
    - hydrator: subscription_hydrator
    - authorizer: allow_all_authorizer
    - mutator: jwt
  on_error:
    - error_handler: default
`),
				},
			},
			configureMocks: func(t *testing.T, factory *mocks.MockRuleFactory) {
				t.Helper()

				factory.On("CreateRule", "test", mock.MatchedBy(
					func(conf config.RuleConfig) bool {
						assert.Equal(t, "rule:foo", conf.ID)
						assert.Equal(t, "http://foo.bar/<**>", conf.URL)
						assert.Equal(t, "regex", conf.MatchingStrategy)
						assert.ElementsMatch(t, conf.Methods, []string{"PATCH"})
						require.Len(t, conf.Execute, 4)
						require.Len(t, conf.ErrorHandler, 1)

						assert.Len(t, conf.Execute[0], 1)
						assert.Equal(t, "unauthorized_authenticator", conf.Execute[0]["authenticator"])

						assert.Len(t, conf.Execute[1], 1)
						assert.Equal(t, "subscription_hydrator", conf.Execute[1]["hydrator"])

						assert.Len(t, conf.Execute[2], 1)
						assert.Equal(t, "allow_all_authorizer", conf.Execute[2]["authorizer"])

						assert.Len(t, conf.Execute[3], 1)
						assert.Equal(t, "jwt", conf.Execute[3]["mutator"])

						assert.Len(t, conf.ErrorHandler[0], 1)
						assert.Equal(t, "default", conf.ErrorHandler[0]["error_handler"])

						return true
					})).Return(&ruleImpl{id: "test", srcID: "test"}, nil)
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.rules, 1)
				assert.Equal(t, &ruleImpl{id: "test", srcID: "test"}, repo.rules[0])
			},
		},
		{
			uc: "multiple rule sets",
			events: []event.RuleSetChangedEvent{
				{
					Src:        "test1",
					ChangeType: event.Create,
					Definition: []byte(`
- id: rule:bar
  url: http://bar.foo/<**>
  methods:
   - GET
`),
				},
				{
					Src:        "test2",
					ChangeType: event.Create,
					Definition: []byte(`
- id: rule:foo
  url: http://foo.bar/<**>
  methods:
   - POST
`),
				},
			},
			configureMocks: func(t *testing.T, factory *mocks.MockRuleFactory) {
				t.Helper()

				factory.On("CreateRule", "test1", mock.Anything).
					Return(&ruleImpl{id: "rule:bar", srcID: "test1"}, nil)

				factory.On("CreateRule", "test2", mock.Anything).
					Return(&ruleImpl{id: "rule:foo", srcID: "test2"}, nil)
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.rules, 2)
				assert.Equal(t, &ruleImpl{id: "rule:bar", srcID: "test1"}, repo.rules[0])
				assert.Equal(t, &ruleImpl{id: "rule:foo", srcID: "test2"}, repo.rules[1])
			},
		},
		{
			uc: "multiple rule sets created and one of these deleted",
			events: []event.RuleSetChangedEvent{
				{
					Src:        "test1",
					ChangeType: event.Create,
					Definition: []byte(`
- id: rule:bar
  url: http://bar.foo/<**>
  methods:
   - GET
`),
				},
				{
					Src:        "test2",
					ChangeType: event.Create,
					Definition: []byte(`
- id: rule:foo
  url: http://foo.bar/<**>
  methods:
   - POST
`),
				},
				{
					Src:        "test2",
					ChangeType: event.Remove,
				},
			},
			configureMocks: func(t *testing.T, factory *mocks.MockRuleFactory) {
				t.Helper()

				factory.On("CreateRule", "test1", mock.Anything).
					Return(&ruleImpl{id: "rule:bar", srcID: "test1"}, nil)

				factory.On("CreateRule", "test2", mock.Anything).
					Return(&ruleImpl{id: "rule:foo", srcID: "test2"}, nil)
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.rules, 1)
				assert.Equal(t, &ruleImpl{id: "rule:bar", srcID: "test1"}, repo.rules[0])
			},
		},
		{
			uc: "error while creating rule",
			events: []event.RuleSetChangedEvent{
				{
					Src:        "test",
					ChangeType: event.Create,
					Definition: []byte(`
- id: rule:bar
  url: http://bar.foo/<**>
  methods:
   - GET
`),
				},
			},
			configureMocks: func(t *testing.T, factory *mocks.MockRuleFactory) {
				t.Helper()

				factory.On("CreateRule", "test", mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.rules, 0)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			impl.rules = make([]rule.Rule, defaultRuleListSize)

			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, factory *mocks.MockRuleFactory) { t.Helper() })

			factory := &mocks.MockRuleFactory{}
			configureMocks(t, factory)

			impl.rf = factory

			// WHEN
			for _, evt := range tc.events {
				queue <- evt
			}

			time.Sleep(100 * time.Millisecond)

			// THEN
			tc.assert(t, impl)
			factory.AssertExpectations(t)
		})
	}
}
