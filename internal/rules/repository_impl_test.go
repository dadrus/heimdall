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
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/patternmatcher"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestRepositoryAddAndRemoveRulesFromSameRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(nil, &ruleFactory{}, *zerolog.Ctx(context.Background()))

	// WHEN
	repo.addRuleSet("bar", []rule.Rule{
		&ruleImpl{id: "1", srcID: "bar"},
		&ruleImpl{id: "2", srcID: "bar"},
		&ruleImpl{id: "3", srcID: "bar"},
		&ruleImpl{id: "4", srcID: "bar"},
	})

	// THEN
	assert.Len(t, repo.rules, 4)

	// WHEN
	repo.deleteRuleSet("bar")

	// THEN
	assert.Empty(t, repo.rules)
}

func TestRepositoryFindRule(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		requestURL       *url.URL
		addRules         func(t *testing.T, repo *repository)
		configureFactory func(t *testing.T, factory *mocks.FactoryMock)
		assert           func(t *testing.T, err error, rul rule.Rule)
	}{
		{
			uc:         "no matching rule without default rule",
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
			assert: func(t *testing.T, err error, _ rule.Rule) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrNoRuleFound)
			},
		},
		{
			uc:         "no matching rule with default rule",
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(true)
				factory.EXPECT().DefaultRule().Return(&ruleImpl{id: "test", isDefault: true})
			},
			assert: func(t *testing.T, err error, rul rule.Rule) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, &ruleImpl{id: "test", isDefault: true}, rul)
			},
		},
		{
			uc:         "matching rule",
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
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
			addRules := x.IfThenElse(tc.addRules != nil,
				tc.addRules,
				func(t *testing.T, _ *repository) { t.Helper() })

			factory := mocks.NewFactoryMock(t)
			tc.configureFactory(t, factory)

			repo := newRepository(nil, factory, *zerolog.Ctx(context.Background()))

			addRules(t, repo)

			// WHEN
			rul, err := repo.FindRule(tc.requestURL)

			// THEN
			tc.assert(t, err, rul)
		})
	}
}

func TestRepositoryAddAndRemoveRulesFromDifferentRuleSets(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(nil, &ruleFactory{}, *zerolog.Ctx(context.Background()))

	// WHEN
	repo.addRules([]rule.Rule{
		&ruleImpl{id: "1", srcID: "bar"},
		&ruleImpl{id: "2", srcID: "baz"},
		&ruleImpl{id: "3", srcID: "bar"},
		&ruleImpl{id: "4", srcID: "bar"},
		&ruleImpl{id: "4", srcID: "foo"},
	})

	// THEN
	assert.Len(t, repo.rules, 5)

	// WHEN
	repo.deleteRuleSet("bar")

	// THEN
	assert.Len(t, repo.rules, 2)
	assert.ElementsMatch(t, repo.rules, []rule.Rule{
		&ruleImpl{id: "2", srcID: "baz"},
		&ruleImpl{id: "4", srcID: "foo"},
	})

	// WHEN
	repo.deleteRuleSet("foo")

	// THEN
	assert.Len(t, repo.rules, 1)
	assert.ElementsMatch(t, repo.rules, []rule.Rule{
		&ruleImpl{id: "2", srcID: "baz"},
	})

	// WHEN
	repo.deleteRuleSet("baz")

	// THEN
	assert.Empty(t, repo.rules)
}

func TestRepositoryRuleSetLifecycleManagement(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		events []event.RuleSetChanged
		assert func(t *testing.T, repo *repository)
	}{
		{
			uc:     "empty rule set definition",
			events: []event.RuleSetChanged{{Source: "test", ChangeType: event.Create}},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Empty(t, repo.rules)
			},
		},
		{
			uc: "rule set with one rule",
			events: []event.RuleSetChanged{
				{
					Source:     "test",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:foo", srcID: "test"}},
				},
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.rules, 1)
				assert.Equal(t, &ruleImpl{id: "rule:foo", srcID: "test"}, repo.rules[0])
			},
		},
		{
			uc: "multiple rule sets",
			events: []event.RuleSetChanged{
				{
					Source:     "test1",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:bar", srcID: "test1"}},
				},
				{
					Source:     "test2",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:foo", srcID: "test2"}},
				},
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
			events: []event.RuleSetChanged{
				{
					Source:     "test1",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:bar", srcID: "test1"}},
				},
				{
					Source:     "test2",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:foo", srcID: "test2"}},
				},
				{
					Source:     "test2",
					ChangeType: event.Remove,
				},
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.rules, 1)
				assert.Equal(t, &ruleImpl{id: "rule:bar", srcID: "test1"}, repo.rules[0])
			},
		},
		{
			uc: "multiple rule sets created and one updated",
			events: []event.RuleSetChanged{
				{
					Source:     "test1",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:bar", srcID: "test1"}},
				},
				{
					Source:     "test2",
					ChangeType: event.Create,
					Rules: []rule.Rule{
						&ruleImpl{id: "rule:bar", srcID: "test2", hash: []byte{1}},
						&ruleImpl{id: "rule:foo2", srcID: "test2", hash: []byte{2}},
						&ruleImpl{id: "rule:foo3", srcID: "test2", hash: []byte{3}},
						&ruleImpl{id: "rule:foo4", srcID: "test2", hash: []byte{4}},
					},
				},
				{
					Source:     "test2",
					ChangeType: event.Update,
					Rules: []rule.Rule{
						&ruleImpl{id: "rule:bar", srcID: "test2", hash: []byte{5}},  // updated
						&ruleImpl{id: "rule:foo2", srcID: "test2", hash: []byte{2}}, // as before
						// &ruleImpl{id: "rule:foo3", srcID: "test2", hash: []byte{3}}, // deleted
						&ruleImpl{id: "rule:foo4", srcID: "test2", hash: []byte{4}}, // as before
					},
				},
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				require.Len(t, repo.rules, 4)
				assert.ElementsMatch(t, repo.rules, []rule.Rule{
					&ruleImpl{id: "rule:bar", srcID: "test1"},
					&ruleImpl{id: "rule:bar", srcID: "test2", hash: []byte{5}},
					&ruleImpl{id: "rule:foo2", srcID: "test2", hash: []byte{2}},
					&ruleImpl{id: "rule:foo4", srcID: "test2", hash: []byte{4}},
				})
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			ctx := context.Background()

			queue := make(event.RuleSetChangedEventQueue, 10)
			defer close(queue)

			repo := newRepository(queue, &ruleFactory{}, log.Logger)
			require.NoError(t, repo.Start(ctx))

			defer repo.Stop(ctx)

			// WHEN
			for _, evt := range tc.events {
				queue <- evt
			}

			time.Sleep(100 * time.Millisecond)

			// THEN
			tc.assert(t, repo)
		})
	}
}
