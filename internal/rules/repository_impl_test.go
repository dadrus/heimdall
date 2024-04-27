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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	mocks2 "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/config"
	mocks3 "github.com/dadrus/heimdall/internal/rules/config/mocks"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/radixtree"
)

func TestRepositoryAddRuleSetWithoutViolation(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert
	rules := []rule.Rule{
		&ruleImpl{id: "1", srcID: "1", pathExpression: "/foo/1"},
	}

	// WHEN
	err := repo.AddRuleSet("1", rules)

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 1)
	assert.False(t, repo.index.Empty())
	assert.ElementsMatch(t, repo.knownRules, rules)
	_, err = repo.index.Find("/foo/1", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	require.NoError(t, err)
}

func TestRepositoryAddRuleSetWithViolation(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert
	rules1 := []rule.Rule{&ruleImpl{id: "1", srcID: "1", pathExpression: "/foo/1"}}
	rules2 := []rule.Rule{&ruleImpl{id: "2", srcID: "2", pathExpression: "/foo/1"}}

	require.NoError(t, repo.AddRuleSet("1", rules1))

	// WHEN
	err := repo.AddRuleSet("2", rules2)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, radixtree.ErrConstraintsViolation)

	assert.Len(t, repo.knownRules, 1)
	assert.False(t, repo.index.Empty())
	assert.ElementsMatch(t, repo.knownRules, rules1)
	_, err = repo.index.Find("/foo/1", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	require.NoError(t, err)
}

func TestRepositoryRemoveRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert
	rules1 := []rule.Rule{
		&ruleImpl{id: "1", srcID: "1", pathExpression: "/foo/1"},
		&ruleImpl{id: "2", srcID: "1", pathExpression: "/foo/2"},
		&ruleImpl{id: "3", srcID: "1", pathExpression: "/foo/3"},
		&ruleImpl{id: "4", srcID: "1", pathExpression: "/foo/4"},
	}

	require.NoError(t, repo.AddRuleSet("1", rules1))
	assert.Len(t, repo.knownRules, 4)
	assert.False(t, repo.index.Empty())

	// WHEN
	err := repo.DeleteRuleSet("1")

	// THEN
	require.NoError(t, err)
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.index.Empty())
}

func TestRepositoryRemoveRulesFromDifferentRuleSets(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	rules1 := []rule.Rule{
		&ruleImpl{id: "1", srcID: "bar", pathExpression: "/bar/1"},
		&ruleImpl{id: "3", srcID: "bar", pathExpression: "/bar/3"},
		&ruleImpl{id: "4", srcID: "bar", pathExpression: "/bar/4"},
	}
	rules2 := []rule.Rule{
		&ruleImpl{id: "2", srcID: "baz", pathExpression: "/baz/2"},
	}
	rules3 := []rule.Rule{
		&ruleImpl{id: "4", srcID: "foo", pathExpression: "/foo/4"},
	}

	// WHEN
	require.NoError(t, repo.AddRuleSet("bar", rules1))
	require.NoError(t, repo.AddRuleSet("baz", rules2))
	require.NoError(t, repo.AddRuleSet("foo", rules3))

	// THEN
	assert.Len(t, repo.knownRules, 5)
	assert.False(t, repo.index.Empty())

	// WHEN
	err := repo.DeleteRuleSet("bar")

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 2)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules2[0], rules3[0]})

	_, err = repo.index.Find("/bar/1", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/bar/3", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/bar/4", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/baz/2", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	_, err = repo.index.Find("/foo/4", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	err = repo.DeleteRuleSet("foo")

	// THEN
	require.NoError(t, err)
	assert.Len(t, repo.knownRules, 1)
	assert.ElementsMatch(t, repo.knownRules, []rule.Rule{rules2[0]})

	_, err = repo.index.Find("/foo/4", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/baz/2", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	// WHEN
	err = repo.DeleteRuleSet("baz")

	// THEN
	require.NoError(t, err)
	assert.Empty(t, repo.knownRules)
	assert.True(t, repo.index.Empty())
}

func TestRepositoryUpdateRuleSet(t *testing.T) {
	t.Parallel()

	// GIVEN
	repo := newRepository(&ruleFactory{}).(*repository) //nolint: forcetypeassert

	initialRules := []rule.Rule{
		&ruleImpl{id: "1", srcID: "1", pathExpression: "/bar/1", hash: []byte{1}},
		&ruleImpl{id: "2", srcID: "1", pathExpression: "/bar/2", hash: []byte{1}},
		&ruleImpl{id: "3", srcID: "1", pathExpression: "/bar/3", hash: []byte{1}},
		&ruleImpl{id: "4", srcID: "1", pathExpression: "/bar/4", hash: []byte{1}},
	}

	require.NoError(t, repo.AddRuleSet("1", initialRules))

	updatedRules := []rule.Rule{
		&ruleImpl{id: "1", srcID: "1", pathExpression: "/bar/1", hash: []byte{2}}, // changed
		// rule with id 2 is deleted
		&ruleImpl{id: "3", srcID: "1", pathExpression: "/foo/3", hash: []byte{2}}, // changed and path expression changed
		&ruleImpl{id: "4", srcID: "1", pathExpression: "/bar/4", hash: []byte{1}}, // same as before
	}

	// WHEN
	err := repo.UpdateRuleSet("1", updatedRules)

	// THEN
	require.NoError(t, err)

	assert.Len(t, repo.knownRules, 3)
	assert.False(t, repo.index.Empty())

	_, err = repo.index.Find("/bar/1", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	_, err = repo.index.Find("/bar/2", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/bar/3", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.Error(t, err) //nolint:testifylint

	_, err = repo.index.Find("/foo/3", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint

	_, err = repo.index.Find("/bar/4", radixtree.MatcherFunc[rule.Rule](func(_ rule.Rule) bool { return true }))
	assert.NoError(t, err) //nolint:testifylint
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

				err := repo.AddRuleSet("baz", []rule.Rule{
					&ruleImpl{
						id:             "test2",
						srcID:          "baz",
						pathExpression: "/baz/bar",
						matcher: func() config.RequestMatcher {
							rm := mocks3.NewRequestMatcherMock(t)
							rm.EXPECT().Matches(mock.Anything).Return(nil)

							return rm
						}(),
					},
				})
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
			ctx := mocks2.NewContextMock(t)
			ctx.EXPECT().AppContext().Maybe().Return(context.TODO())
			ctx.EXPECT().Request().Return(req)

			// WHEN
			rul, err := repo.FindRule(ctx)

			// THEN
			tc.assert(t, err, rul)
		})
	}
}
