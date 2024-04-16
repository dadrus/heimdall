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
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/indextree"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

type testMatcher bool

func (m testMatcher) Match(_ string) bool { return bool(m) }

func TestRepositoryAddAndRemoveRulesFromSameRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(nil, &ruleFactory{}, *zerolog.Ctx(context.Background()))

	// WHEN
	repo.addRuleSet("bar", []rule.Rule{
		&ruleImpl{id: "1", srcID: "bar", pathExpression: "/foo/1"},
		&ruleImpl{id: "2", srcID: "bar", pathExpression: "/foo/2"},
		&ruleImpl{id: "3", srcID: "bar", pathExpression: "/foo/3"},
		&ruleImpl{id: "4", srcID: "bar", pathExpression: "/foo/4"},
	})

	// THEN
	assert.Len(t, repo.knownRules, 4)
	assert.False(t, repo.rulesTree.Empty())

	// WHEN
	repo.deleteRuleSet("bar")

	// THEN
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.rulesTree.Empty())
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
			uc:         "no matching rule",
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
			uc:         "matches default rule",
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
			uc:         "matches upstream rule",
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
			addRules: func(t *testing.T, repo *repository) {
				t.Helper()

				fooBarMatcher, err := newGlobMatcher("foo.bar", '.')
				require.NoError(t, err)

				exampleComMatcher, err := newGlobMatcher("example.com", '.')
				require.NoError(t, err)

				repo.addRuleSet("bar", []rule.Rule{
					&ruleImpl{
						id:             "test1",
						srcID:          "bar",
						pathExpression: "/baz",
						hostMatcher:    exampleComMatcher,
						pathMatcher:    testMatcher(true),
						allowedMethods: []string{http.MethodGet},
					},
				})

				repo.addRuleSet("baz", []rule.Rule{
					&ruleImpl{
						id:             "test2",
						srcID:          "baz",
						pathExpression: "/baz",
						hostMatcher:    fooBarMatcher,
						pathMatcher:    testMatcher(true),
						allowedMethods: []string{http.MethodGet},
					},
				})
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

			req := &heimdall.Request{Method: http.MethodGet, URL: &heimdall.URL{URL: *tc.requestURL}}

			// WHEN
			rul, err := repo.FindRule(req)

			// THEN
			tc.assert(t, err, rul)
		})
	}
}

func TestRepositoryAddAndRemoveRulesFromDifferentRuleSets(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(nil, &ruleFactory{}, *zerolog.Ctx(context.Background()))

	rules := []rule.Rule{
		&ruleImpl{
			id: "1", srcID: "bar", pathExpression: "/bar/1",
			hostMatcher: testMatcher(true), pathMatcher: testMatcher(true), allowedMethods: []string{http.MethodGet},
		},
		&ruleImpl{
			id: "2", srcID: "baz", pathExpression: "/baz/2",
			hostMatcher: testMatcher(true), pathMatcher: testMatcher(true), allowedMethods: []string{http.MethodGet},
		},
		&ruleImpl{
			id: "3", srcID: "bar", pathExpression: "/bar/3",
			hostMatcher: testMatcher(true), pathMatcher: testMatcher(true), allowedMethods: []string{http.MethodGet},
		},
		&ruleImpl{
			id: "4", srcID: "bar", pathExpression: "/bar/4",
			hostMatcher: testMatcher(true), pathMatcher: testMatcher(true), allowedMethods: []string{http.MethodGet},
		},
		&ruleImpl{
			id: "4", srcID: "foo", pathExpression: "/foo/4",
			hostMatcher: testMatcher(true), pathMatcher: testMatcher(true), allowedMethods: []string{http.MethodGet},
		},
	}

	// WHEN
	repo.addRules(rules)

	// THEN
	assert.Len(t, repo.knownRules, 5)
	assert.False(t, repo.rulesTree.Empty())

	// WHEN
	repo.deleteRuleSet("bar")

	// THEN
	assert.Len(t, repo.knownRules, 2)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules[1], rules[4]})

	_, _, err := repo.rulesTree.Find("/bar/1", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, _, err = repo.rulesTree.Find("/bar/3", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, _, err = repo.rulesTree.Find("/bar/4", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, _, err = repo.rulesTree.Find("/baz/2", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	_, _, err = repo.rulesTree.Find("/foo/4", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	repo.deleteRuleSet("foo")

	// THEN
	assert.Len(t, repo.knownRules, 1)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules[1]})

	_, _, err = repo.rulesTree.Find("/foo/4", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, _, err = repo.rulesTree.Find("/baz/2", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	repo.deleteRuleSet("baz")

	// THEN
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.rulesTree.Empty())
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

				assert.Empty(t, repo.knownRules)
				assert.True(t, repo.rulesTree.Empty())
			},
		},
		{
			uc: "rule set with one rule",
			events: []event.RuleSetChanged{
				{
					Source:     "test",
					ChangeType: event.Create,
					Rules: []rule.Rule{
						&ruleImpl{id: "rule:foo", srcID: "test", pathExpression: "/foo/1"},
					},
				},
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.knownRules, 1)
				assert.False(t, repo.rulesTree.Empty())

				rul, _, err := repo.rulesTree.Find("/foo/1", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)

				assert.Equal(t, repo.knownRules[0], rul)
				assert.Equal(t, "rule:foo", rul.ID())
				assert.Equal(t, "test", rul.SrcID())
			},
		},
		{
			uc: "multiple rule sets",
			events: []event.RuleSetChanged{
				{
					Source:     "test1",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:bar", srcID: "test1", pathExpression: "/bar/1"}},
				},
				{
					Source:     "test2",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:foo", srcID: "test2", pathExpression: "/foo/1"}},
				},
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.knownRules, 2)

				rul1, _, err := repo.rulesTree.Find("/bar/1", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, repo.knownRules[0], rul1)
				assert.Equal(t, "rule:bar", rul1.ID())
				assert.Equal(t, "test1", rul1.SrcID())

				rul2, _, err := repo.rulesTree.Find("/foo/1", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, repo.knownRules[1], rul2)
				assert.Equal(t, "rule:foo", rul2.ID())
				assert.Equal(t, "test2", rul2.SrcID())
			},
		},
		{
			uc: "multiple rule sets created and one of these deleted",
			events: []event.RuleSetChanged{
				{
					Source:     "test1",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:bar", srcID: "test1", pathExpression: "/bar/1"}},
				},
				{
					Source:     "test2",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:foo", srcID: "test2", pathExpression: "/foo/1"}},
				},
				{
					Source:     "test1",
					ChangeType: event.Remove,
				},
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				assert.Len(t, repo.knownRules, 1)
				assert.False(t, repo.rulesTree.Empty())

				rul, _, err := repo.rulesTree.Find("/foo/1", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)

				assert.Equal(t, repo.knownRules[0], rul)
				assert.Equal(t, "rule:foo", rul.ID())
				assert.Equal(t, "test2", rul.SrcID())
			},
		},
		{
			uc: "multiple rule sets created and one updated",
			events: []event.RuleSetChanged{
				{
					Source:     "test1",
					ChangeType: event.Create,
					Rules:      []rule.Rule{&ruleImpl{id: "rule:bar", srcID: "test1", pathExpression: "/bar/1"}},
				},
				{
					Source:     "test2",
					ChangeType: event.Create,
					Rules: []rule.Rule{
						&ruleImpl{id: "rule:foo1", srcID: "test2", hash: []byte{1}, pathExpression: "/foo/1"},
						&ruleImpl{id: "rule:foo2", srcID: "test2", hash: []byte{2}, pathExpression: "/foo/2"},
						&ruleImpl{id: "rule:foo3", srcID: "test2", hash: []byte{3}, pathExpression: "/foo/3"},
						&ruleImpl{id: "rule:foo4", srcID: "test2", hash: []byte{4}, pathExpression: "/foo/4"},
					},
				},
				{
					Source:     "test2",
					ChangeType: event.Update,
					Rules: []rule.Rule{
						&ruleImpl{id: "rule:foo1", srcID: "test2", hash: []byte{5}, pathExpression: "/foo/1"}, // updated
						&ruleImpl{id: "rule:foo2", srcID: "test2", hash: []byte{2}, pathExpression: "/foo/2"}, // as before
						// &ruleImpl{id: "rule:foo3", srcID: "test2", hash: []byte{3}, pathExpression: "/foo/3"}, // deleted
						&ruleImpl{id: "rule:foo4", srcID: "test2", hash: []byte{4}, pathExpression: "/foo/4"}, // as before
					},
				},
			},
			assert: func(t *testing.T, repo *repository) {
				t.Helper()

				require.Len(t, repo.knownRules, 4)
				assert.False(t, repo.rulesTree.Empty())

				rulBar, _, err := repo.rulesTree.Find("/bar/1", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, repo.knownRules[0], rulBar)
				assert.Equal(t, "rule:bar", rulBar.ID())
				assert.Equal(t, "test1", rulBar.SrcID())

				rulFoo1, _, err := repo.rulesTree.Find("/foo/1", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, repo.knownRules[1], rulFoo1)
				assert.Equal(t, "rule:foo1", rulFoo1.ID())
				assert.Equal(t, "test2", rulFoo1.SrcID())
				assert.Equal(t, []byte{5}, rulFoo1.(*ruleImpl).hash) //nolint: forcetypeassert

				rulFoo2, _, err := repo.rulesTree.Find("/foo/2", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, repo.knownRules[2], rulFoo2)
				assert.Equal(t, "rule:foo2", rulFoo2.ID())
				assert.Equal(t, "test2", rulFoo2.SrcID())
				assert.Equal(t, []byte{2}, rulFoo2.(*ruleImpl).hash) //nolint: forcetypeassert

				rulFoo4, _, err := repo.rulesTree.Find("/foo/4", indextree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
				require.NoError(t, err)
				assert.Equal(t, repo.knownRules[3], rulFoo4)
				assert.Equal(t, "rule:foo4", rulFoo4.ID())
				assert.Equal(t, "test2", rulFoo4.SrcID())
				assert.Equal(t, []byte{4}, rulFoo4.(*ruleImpl).hash) //nolint: forcetypeassert
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
