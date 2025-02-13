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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	mocks2 "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/radixtree"
)

func TestRepositoryAddRuleSetWithoutViolation(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "1"}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/foo/1"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/foo/2"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/foo/3"})

	rules := []rule.Rule{rule1}

	// WHEN
	err := repo.AddRuleSet(context.TODO(), "1", rules)

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 1)
	assert.False(t, repo.index.Empty())
	assert.ElementsMatch(t, repo.knownRules, rules)

	_, err = repo.index.Find("/foo/1", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.Find("/foo/2", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.Find("/foo/3", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
}

func TestRepositoryAddRuleSetWithViolation(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "1"}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/foo/1"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/foo/2"})

	rule2 := &ruleImpl{id: "2", srcID: "2"}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, path: "/foo/1"})

	rules1 := []rule.Rule{rule1}
	rules2 := []rule.Rule{rule2}

	require.NoError(t, repo.AddRuleSet(context.TODO(), "1", rules1))

	// WHEN
	err := repo.AddRuleSet(context.TODO(), "2", rules2)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, radixtree.ErrConstraintsViolation)

	assert.Len(t, repo.knownRules, 1)
	assert.False(t, repo.index.Empty())
	assert.ElementsMatch(t, repo.knownRules, rules1)
	_, err = repo.index.Find("/foo/1", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.Find("/foo/1", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
}

func TestRepositoryRemoveRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "1"}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/foo/1"})

	rule2 := &ruleImpl{id: "2", srcID: "1"}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, path: "/foo/2"})

	rule3 := &ruleImpl{id: "3", srcID: "1"}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, path: "/foo/4"})

	rule4 := &ruleImpl{id: "4", srcID: "1"}
	rule4.routes = append(rule4.routes, &routeImpl{rule: rule4, path: "/foo/4"})

	rules := []rule.Rule{rule1, rule2, rule3, rule4}

	require.NoError(t, repo.AddRuleSet(context.TODO(), "1", rules))
	assert.Len(t, repo.knownRules, 4)
	assert.False(t, repo.index.Empty())

	// WHEN
	err := repo.DeleteRuleSet(context.TODO(), "1")

	// THEN
	require.NoError(t, err)
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.index.Empty())
}

func TestRepositoryRemoveRulesFromDifferentRuleSets(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "bar"}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/bar/1"})

	rule2 := &ruleImpl{id: "3", srcID: "bar"}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, path: "/bar/3"})

	rule3 := &ruleImpl{id: "4", srcID: "bar"}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, path: "/bar/4"})

	rule4 := &ruleImpl{id: "2", srcID: "baz"}
	rule4.routes = append(rule4.routes, &routeImpl{rule: rule4, path: "/baz/2"})

	rule5 := &ruleImpl{id: "4", srcID: "foo"}
	rule5.routes = append(rule5.routes, &routeImpl{rule: rule5, path: "/foo/4"})

	rules1 := []rule.Rule{rule1, rule2, rule3}
	rules2 := []rule.Rule{rule4}
	rules3 := []rule.Rule{rule5}

	// WHEN
	require.NoError(t, repo.AddRuleSet(context.TODO(), "bar", rules1))
	require.NoError(t, repo.AddRuleSet(context.TODO(), "baz", rules2))
	require.NoError(t, repo.AddRuleSet(context.TODO(), "foo", rules3))

	// THEN
	assert.Len(t, repo.knownRules, 5)
	assert.False(t, repo.index.Empty())

	// WHEN
	err := repo.DeleteRuleSet(context.TODO(), "bar")

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 2)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules2[0], rules3[0]})

	_, err = repo.index.Find("/bar/1", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/bar/3", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/bar/4", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/baz/2", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	_, err = repo.index.Find("/foo/4", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	err = repo.DeleteRuleSet(context.TODO(), "foo")

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 1)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules2[0]})

	_, err = repo.index.Find("/foo/4", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/baz/2", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	err = repo.DeleteRuleSet(context.TODO(), "baz")

	// THEN
	require.NoError(t, err)
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.index.Empty())
}

func TestRepositoryUpdateRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rule1 := &ruleImpl{id: "1", srcID: "1", hash: []byte{1}}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/bar/1"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/bar/1a"})

	rule2 := &ruleImpl{id: "2", srcID: "1", hash: []byte{1}}
	rule2.routes = append(rule2.routes, &routeImpl{rule: rule2, path: "/bar/2"})

	rule3 := &ruleImpl{id: "3", srcID: "1", hash: []byte{1}}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, path: "/bar/3"})

	rule4 := &ruleImpl{id: "4", srcID: "1", hash: []byte{1}}
	rule4.routes = append(rule4.routes, &routeImpl{rule: rule4, path: "/bar/4"})

	initialRules := []rule.Rule{rule1, rule2, rule3, rule4}

	require.NoError(t, repo.AddRuleSet(context.TODO(), "1", initialRules))

	// rule 1 changed: /bar/1a gone, /bar/1b added
	rule1 = &ruleImpl{id: "1", srcID: "1", hash: []byte{2}}
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/bar/1"})
	rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/bar/1b"})
	// rule with id 2 is deleted
	// rule 3 changed: /bar/2 gone, /foo/3 and /foo/4 added
	rule3 = &ruleImpl{id: "3", srcID: "1", hash: []byte{2}}
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, path: "/foo/3"})
	rule3.routes = append(rule3.routes, &routeImpl{rule: rule3, path: "/foo/4"})
	// rule 4 same as before

	updatedRules := []rule.Rule{rule1, rule3, rule4}

	// WHEN
	err := repo.UpdateRuleSet(context.TODO(), "1", updatedRules)

	// THEN
	require.NoError(t, err)

	assert.Len(t, repo.knownRules, 3)
	assert.False(t, repo.index.Empty())

	_, err = repo.index.Find("/bar/1", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.Find("/bar/1a", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)
	_, err = repo.index.Find("/bar/1b", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)

	_, err = repo.index.Find("/bar/2", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)

	_, err = repo.index.Find("/bar/3", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.Error(t, err)
	_, err = repo.index.Find("/foo/3", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
	_, err = repo.index.Find("/foo/4", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)

	_, err = repo.index.Find("/bar/4", radixtree.LookupMatcherFunc[rule.Route](func(_ rule.Route, _, _ []string) bool { return true }))
	require.NoError(t, err)
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
			requestURL: &url.URL{Scheme: "http", Host: "foo.bar", Path: "/baz/bar"},
			configureFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().HasDefaultRule().Return(false)
			},
			addRules: func(t *testing.T, repo *repository) {
				t.Helper()

				rule1 := &ruleImpl{id: "test2", srcID: "baz", hash: []byte{1}}
				rule1.routes = append(rule1.routes, &routeImpl{rule: rule1, path: "/baz/bar", matcher: compositeMatcher{}})

				err := repo.AddRuleSet(context.TODO(), "baz", []rule.Rule{rule1})
				require.NoError(t, err)
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

			repo := newRepository(factory).(*repository) //nolint: forcetypeassert

			addRules(t, repo)

			req := &heimdall.Request{Method: http.MethodGet, URL: &heimdall.URL{URL: *tc.requestURL}}
			ctx := mocks2.NewRequestContextMock(t)
			ctx.EXPECT().Context().Maybe().Return(context.TODO())
			ctx.EXPECT().Request().Return(req)

			// WHEN
			rul, err := repo.FindRule(ctx)

			// THEN
			tc.assert(t, err, rul)
		})
	}
}
