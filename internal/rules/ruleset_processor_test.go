// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
)

func TestRuleSetProcessorOnCreated(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ruleset   v1beta1.RuleSet
		configure func(
			t *testing.T,
			factory *mocks.FactoryMock,
			repo *mocks.RepositoryMock,
			scopeFactory *secretsmocks.ScopedResolverFactoryMock,
			resolver *secretsmocks.ScopedResolverMock,
		)
		assert func(t *testing.T, processor *ruleSetProcessor, err error)
	}{
		"unsupported version": {
			ruleset: v1beta1.RuleSet{Version: "foo"},
			configure: func(
				t *testing.T,
				_ *mocks.FactoryMock,
				_ *mocks.RepositoryMock,
				_ *secretsmocks.ScopedResolverFactoryMock,
				_ *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()
			},
			assert: func(t *testing.T, _ *ruleSetProcessor, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedRuleSetVersion)
			},
		},
		"error while loading rule set releases newly created resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				factory *mocks.FactoryMock,
				_ *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				resolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(resolver)

				factory.EXPECT().
					CreateRule(
						resolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(nil, assert.AnError)

				resolver.EXPECT().
					Release().
					Once()
			},
			assert: func(t *testing.T, processor *ruleSetProcessor, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "loading rule ID='foo' failed")
				require.ErrorIs(t, err, assert.AnError)
				require.NotContains(t, processor.scopes, "test")
			},
		},
		"error while awaiting readiness releases newly created resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				factory *mocks.FactoryMock,
				_ *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				resolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				rul := mocks.NewRuleMock(t)

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(resolver)

				factory.EXPECT().
					CreateRule(
						resolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(rul, nil)

				resolver.EXPECT().
					AwaitReady(mock.Anything).
					Return(assert.AnError)

				resolver.EXPECT().
					Release().
					Once()
			},
			assert: func(t *testing.T, processor *ruleSetProcessor, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "waiting for rule set ID='test' readiness failed")
				require.ErrorIs(t, err, assert.AnError)
				require.NotContains(t, processor.scopes, "test")
			},
		},
		"error while adding rule set releases newly created resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				factory *mocks.FactoryMock,
				repo *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				resolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				rul := mocks.NewRuleMock(t)

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(resolver)

				factory.EXPECT().
					CreateRule(
						resolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(rul, nil)

				resolver.EXPECT().
					AwaitReady(mock.Anything).
					Return(nil)

				repo.EXPECT().
					AddRuleSet(
						mock.Anything,
						rule.RuleSet{
							ID:        "test",
							Name:      "foobar",
							Namespace: "team-a",
						},
						mock.MatchedBy(func(rules []rule.Rule) bool {
							return len(rules) == 1 && rules[0] == rul
						}),
					).
					Return(assert.AnError)

				resolver.EXPECT().
					Release().
					Once()
			},
			assert: func(t *testing.T, processor *ruleSetProcessor, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.NotContains(t, processor.scopes, "test")
			},
		},
		"successful": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				factory *mocks.FactoryMock,
				repo *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				resolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				rul := mocks.NewRuleMock(t)

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(resolver)

				factory.EXPECT().
					CreateRule(
						resolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(rul, nil)

				resolver.EXPECT().
					AwaitReady(mock.Anything).
					Return(nil)

				repo.EXPECT().
					AddRuleSet(
						mock.Anything,
						rule.RuleSet{
							ID:        "test",
							Name:      "foobar",
							Namespace: "team-a",
						},
						mock.MatchedBy(func(rules []rule.Rule) bool {
							return len(rules) == 1 && rules[0] == rul
						}),
					).
					Return(nil)
			},
			assert: func(t *testing.T, processor *ruleSetProcessor, err error) {
				t.Helper()

				require.NoError(t, err)

				scope, ok := processor.scopes["test"]
				require.True(t, ok)
				require.NotNil(t, scope.resolver)
				require.Equal(t, "test", scope.id)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			factory := mocks.NewFactoryMock(t)
			repo := mocks.NewRepositoryMock(t)
			scopeFactory := secretsmocks.NewScopedResolverFactoryMock(t)
			resolver := secretsmocks.NewScopedResolverMock(t)

			tc.configure(t, factory, repo, scopeFactory, resolver)

			processor := NewRuleSetProcessor(
				config.DecisionMode,
				repo,
				factory,
				scopeFactory,
			).(*ruleSetProcessor)

			err := processor.OnCreated(t.Context(), tc.ruleset)

			tc.assert(t, processor, err)
		})
	}
}

func TestRuleSetProcessorOnUpdated(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ruleset   v1beta1.RuleSet
		configure func(
			t *testing.T,
			processor *ruleSetProcessor,
			factory *mocks.FactoryMock,
			repo *mocks.RepositoryMock,
			scopeFactory *secretsmocks.ScopedResolverFactoryMock,
			oldResolver *secretsmocks.ScopedResolverMock,
			newResolver *secretsmocks.ScopedResolverMock,
		)
		assert func(
			t *testing.T,
			processor *ruleSetProcessor,
			oldResolver *secretsmocks.ScopedResolverMock,
			newResolver *secretsmocks.ScopedResolverMock,
			err error,
		)
	}{
		"unsupported version": {
			ruleset: v1beta1.RuleSet{Version: "foo"},
			configure: func(
				t *testing.T,
				_ *ruleSetProcessor,
				_ *mocks.FactoryMock,
				_ *mocks.RepositoryMock,
				_ *secretsmocks.ScopedResolverFactoryMock,
				_ *secretsmocks.ScopedResolverMock,
				_ *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()
			},
			assert: func(
				t *testing.T,
				_ *ruleSetProcessor,
				_ *secretsmocks.ScopedResolverMock,
				_ *secretsmocks.ScopedResolverMock,
				err error,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedRuleSetVersion)
			},
		},
		"error while loading rule set releases newly created resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				processor *ruleSetProcessor,
				factory *mocks.FactoryMock,
				_ *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				oldResolver *secretsmocks.ScopedResolverMock,
				newResolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				processor.scopes["test"] = ruleSetScope{
					resolver: oldResolver,
					id:       "test",
				}

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(newResolver)

				factory.EXPECT().
					CreateRule(
						newResolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(nil, assert.AnError)

				newResolver.EXPECT().
					Release().
					Once()
			},
			assert: func(
				t *testing.T,
				processor *ruleSetProcessor,
				oldResolver *secretsmocks.ScopedResolverMock,
				_ *secretsmocks.ScopedResolverMock,
				err error,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "loading rule ID='foo' failed")
				require.ErrorIs(t, err, assert.AnError)

				scope, ok := processor.scopes["test"]
				require.True(t, ok)
				require.Same(t, oldResolver, scope.resolver)
			},
		},
		"error while awaiting readiness releases newly created resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				processor *ruleSetProcessor,
				factory *mocks.FactoryMock,
				_ *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				oldResolver *secretsmocks.ScopedResolverMock,
				newResolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				rul := mocks.NewRuleMock(t)

				processor.scopes["test"] = ruleSetScope{
					resolver: oldResolver,
					id:       "test",
				}

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(newResolver)

				factory.EXPECT().
					CreateRule(
						newResolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(rul, nil)

				newResolver.EXPECT().
					AwaitReady(mock.Anything).
					Return(assert.AnError)

				newResolver.EXPECT().
					Release().
					Once()
			},
			assert: func(
				t *testing.T,
				processor *ruleSetProcessor,
				oldResolver *secretsmocks.ScopedResolverMock,
				_ *secretsmocks.ScopedResolverMock,
				err error,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "waiting for rule set ID='test' readiness failed")
				require.ErrorIs(t, err, assert.AnError)

				scope, ok := processor.scopes["test"]
				require.True(t, ok)
				require.Same(t, oldResolver, scope.resolver)
			},
		},
		"error while updating rule set releases newly created resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				processor *ruleSetProcessor,
				factory *mocks.FactoryMock,
				repo *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				oldResolver *secretsmocks.ScopedResolverMock,
				newResolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				rul := mocks.NewRuleMock(t)

				processor.scopes["test"] = ruleSetScope{
					resolver: oldResolver,
					id:       "test",
				}

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(newResolver)

				factory.EXPECT().
					CreateRule(
						newResolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(rul, nil)

				newResolver.EXPECT().
					AwaitReady(mock.Anything).
					Return(nil)

				repo.EXPECT().
					UpdateRuleSet(
						mock.Anything,
						rule.RuleSet{
							ID:        "test",
							Name:      "foobar",
							Namespace: "team-a",
						},
						mock.MatchedBy(func(rules []rule.Rule) bool {
							return len(rules) == 1 && rules[0] == rul
						}),
					).
					Return(assert.AnError)

				newResolver.EXPECT().
					Release().
					Once()
			},
			assert: func(
				t *testing.T,
				processor *ruleSetProcessor,
				oldResolver *secretsmocks.ScopedResolverMock,
				_ *secretsmocks.ScopedResolverMock,
				err error,
			) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)

				scope, ok := processor.scopes["test"]
				require.True(t, ok)
				require.Same(t, oldResolver, scope.resolver)
			},
		},
		"successful replaces previous resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(
				t *testing.T,
				processor *ruleSetProcessor,
				factory *mocks.FactoryMock,
				repo *mocks.RepositoryMock,
				scopeFactory *secretsmocks.ScopedResolverFactoryMock,
				oldResolver *secretsmocks.ScopedResolverMock,
				newResolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				rul := mocks.NewRuleMock(t)

				processor.scopes["test"] = ruleSetScope{
					resolver: oldResolver,
					id:       "test",
				}

				scopeFactory.EXPECT().
					Create("test", mock.Anything).
					Return(newResolver)

				factory.EXPECT().
					CreateRule(
						newResolver,
						mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
							return rs.ID == "test" && rs.Namespace == "team-a"
						}),
						v1beta1.Rule{ID: "foo"},
					).
					Return(rul, nil)

				newResolver.EXPECT().
					AwaitReady(mock.Anything).
					Return(nil)

				repo.EXPECT().
					UpdateRuleSet(
						mock.Anything,
						rule.RuleSet{
							ID:        "test",
							Name:      "foobar",
							Namespace: "team-a",
						},
						mock.MatchedBy(func(rules []rule.Rule) bool {
							return len(rules) == 1 && rules[0] == rul
						}),
					).
					Return(nil)

				oldResolver.EXPECT().
					Release().
					Once()
			},
			assert: func(
				t *testing.T,
				processor *ruleSetProcessor,
				_ *secretsmocks.ScopedResolverMock,
				newResolver *secretsmocks.ScopedResolverMock,
				err error,
			) {
				t.Helper()

				require.NoError(t, err)

				scope, ok := processor.scopes["test"]
				require.True(t, ok)
				require.Same(t, newResolver, scope.resolver)
				require.Equal(t, "test", scope.id)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			factory := mocks.NewFactoryMock(t)
			repo := mocks.NewRepositoryMock(t)
			scopeFactory := secretsmocks.NewScopedResolverFactoryMock(t)
			oldResolver := secretsmocks.NewScopedResolverMock(t)
			newResolver := secretsmocks.NewScopedResolverMock(t)

			processor := NewRuleSetProcessor(
				config.DecisionMode,
				repo,
				factory,
				scopeFactory,
			).(*ruleSetProcessor)

			tc.configure(t, processor, factory, repo, scopeFactory, oldResolver, newResolver)

			err := processor.OnUpdated(t.Context(), tc.ruleset)

			tc.assert(t, processor, oldResolver, newResolver, err)
		})
	}
}

func TestRuleSetProcessorOnUpdatedWithoutPreviousRuleSet(t *testing.T) {
	t.Parallel()

	ruleSet := v1beta1.RuleSet{
		MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
		Version:  v1beta1.Version,
		Name:     "foobar",
		Rules:    []v1beta1.Rule{{ID: "foo"}},
	}

	factory := mocks.NewFactoryMock(t)
	repo := mocks.NewRepositoryMock(t)
	scopeFactory := secretsmocks.NewScopedResolverFactoryMock(t)
	resolver := secretsmocks.NewScopedResolverMock(t)
	rul := mocks.NewRuleMock(t)

	processor := NewRuleSetProcessor(
		config.DecisionMode,
		repo,
		factory,
		scopeFactory,
	).(*ruleSetProcessor)

	scopeFactory.EXPECT().
		Create("test", mock.Anything).
		Return(resolver)

	factory.EXPECT().
		CreateRule(
			resolver,
			mock.MatchedBy(func(rs v1beta1.RuleSet) bool {
				return rs.ID == "test" && rs.Namespace == "team-a"
			}),
			v1beta1.Rule{ID: "foo"},
		).
		Return(rul, nil)

	resolver.EXPECT().
		AwaitReady(mock.Anything).
		Return(nil)

	repo.EXPECT().
		UpdateRuleSet(
			mock.Anything,
			rule.RuleSet{
				ID:        "test",
				Name:      "foobar",
				Namespace: "team-a",
			},
			mock.MatchedBy(func(rules []rule.Rule) bool {
				return len(rules) == 1 && rules[0] == rul
			}),
		).
		Return(nil)

	err := processor.OnUpdated(t.Context(), ruleSet)

	require.NoError(t, err)

	scope, ok := processor.scopes["test"]
	require.True(t, ok)
	require.Same(t, resolver, scope.resolver)
	require.Equal(t, "test", scope.id)
}

func TestRuleSetProcessorOnDeleted(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ruleset   v1beta1.RuleSet
		configure func(
			t *testing.T,
			processor *ruleSetProcessor,
			repo *mocks.RepositoryMock,
			resolver *secretsmocks.ScopedResolverMock,
		)
		assert func(t *testing.T, processor *ruleSetProcessor, err error)
	}{
		"failed removing rule set does not release resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
			},
			configure: func(
				t *testing.T,
				processor *ruleSetProcessor,
				repo *mocks.RepositoryMock,
				resolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				processor.scopes["test"] = ruleSetScope{
					resolver: resolver,
					id:       "test",
				}

				repo.EXPECT().
					DeleteRuleSet(
						mock.Anything,
						rule.RuleSet{
							ID:        "test",
							Name:      "foobar",
							Namespace: "team-a",
						},
					).
					Return(assert.AnError)
			},
			assert: func(t *testing.T, processor *ruleSetProcessor, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, assert.AnError)
				require.Contains(t, processor.scopes, "test")
			},
		},
		"successful releases resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
			},
			configure: func(
				t *testing.T,
				processor *ruleSetProcessor,
				repo *mocks.RepositoryMock,
				resolver *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				processor.scopes["test"] = ruleSetScope{
					resolver: resolver,
					id:       "test",
				}

				repo.EXPECT().
					DeleteRuleSet(
						mock.Anything,
						rule.RuleSet{
							ID:        "test",
							Name:      "foobar",
							Namespace: "team-a",
						},
					).
					Return(nil)

				resolver.EXPECT().
					Release().
					Once()
			},
			assert: func(t *testing.T, processor *ruleSetProcessor, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotContains(t, processor.scopes, "test")
			},
		},
		"successful without resolver": {
			ruleset: v1beta1.RuleSet{
				MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
				Version:  v1beta1.Version,
				Name:     "foobar",
			},
			configure: func(
				t *testing.T,
				_ *ruleSetProcessor,
				repo *mocks.RepositoryMock,
				_ *secretsmocks.ScopedResolverMock,
			) {
				t.Helper()

				repo.EXPECT().
					DeleteRuleSet(
						mock.Anything,
						rule.RuleSet{
							ID:        "test",
							Name:      "foobar",
							Namespace: "team-a",
						},
					).
					Return(nil)
			},
			assert: func(t *testing.T, processor *ruleSetProcessor, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotContains(t, processor.scopes, "test")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			repo := mocks.NewRepositoryMock(t)
			factory := mocks.NewFactoryMock(t)
			scopeFactory := secretsmocks.NewScopedResolverFactoryMock(t)
			resolver := secretsmocks.NewScopedResolverMock(t)

			processor := NewRuleSetProcessor(
				config.DecisionMode,
				repo,
				factory,
				scopeFactory,
			).(*ruleSetProcessor)

			tc.configure(t, processor, repo, resolver)

			err := processor.OnDeleted(t.Context(), tc.ruleset)

			tc.assert(t, processor, err)
		})
	}
}

func TestRuleSetProcessorNewScope(t *testing.T) {
	t.Parallel()

	ruleSet := v1beta1.RuleSet{
		MetaData: v1beta1.MetaData{ID: "test", Namespace: "team-a"},
	}

	scopeFactory := secretsmocks.NewScopedResolverFactoryMock(t)
	resolver := secretsmocks.NewScopedResolverMock(t)

	scopeFactory.EXPECT().
		Create("test", mock.Anything).
		Return(resolver).
		Once()

	processor := NewRuleSetProcessor(
		config.DecisionMode,
		mocks.NewRepositoryMock(t),
		mocks.NewFactoryMock(t),
		scopeFactory,
	).(*ruleSetProcessor)

	scope := processor.newScope(ruleSet)

	require.Same(t, resolver, scope.resolver)
	require.Equal(t, "test", scope.id)
}

func TestRuleSetProcessorStoreReplaceAndDeleteScope(t *testing.T) {
	t.Parallel()

	oldResolver := secretsmocks.NewScopedResolverMock(t)
	newResolver := secretsmocks.NewScopedResolverMock(t)

	processor := NewRuleSetProcessor(
		config.DecisionMode,
		mocks.NewRepositoryMock(t),
		mocks.NewFactoryMock(t),
		secretsmocks.NewScopedResolverFactoryMock(t),
	).(*ruleSetProcessor)

	oldScope := ruleSetScope{
		resolver: oldResolver,
		id:       "test",
	}

	newScope := ruleSetScope{
		resolver: newResolver,
		id:       "test",
	}

	processor.storeScope("test", oldScope)

	stored, ok := processor.scopes["test"]
	require.True(t, ok)
	require.Same(t, oldResolver, stored.resolver)

	replaced, ok := processor.replaceScope("test", newScope)
	require.True(t, ok)
	require.Same(t, oldResolver, replaced.resolver)

	stored, ok = processor.scopes["test"]
	require.True(t, ok)
	require.Same(t, newResolver, stored.resolver)

	deleted, ok := processor.deleteScope("test")
	require.True(t, ok)
	require.Same(t, newResolver, deleted.resolver)
	require.NotContains(t, processor.scopes, "test")

	_, ok = processor.deleteScope("test")
	require.False(t, ok)
}
