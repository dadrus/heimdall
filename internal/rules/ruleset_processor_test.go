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
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/api/common"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
)

func TestRuleSetProcessorOnCreated(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ruleset   *v1beta1.RuleSet
		configure func(t *testing.T, mhf *mocks.FactoryMock, repo *mocks.RepositoryMock)
		assert    func(t *testing.T, err error)
	}{
		"unsupported version": {
			ruleset:   &v1beta1.RuleSet{Version: "foo"},
			configure: func(t *testing.T, _ *mocks.FactoryMock, _ *mocks.RepositoryMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedRuleSetVersion)
			},
		},
		"error while loading rule set": {
			ruleset: &v1beta1.RuleSet{Version: v1beta1.Version, Rules: []v1beta1.Rule{{ID: "foo"}}},
			configure: func(t *testing.T, mhf *mocks.FactoryMock, _ *mocks.RepositoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "loading rule ID='foo' failed")
			},
		},
		"error while adding rule set": {
			ruleset: &v1beta1.RuleSet{Version: v1beta1.Version, Rules: []v1beta1.Rule{{ID: "foo"}}},
			configure: func(t *testing.T, mhf *mocks.FactoryMock, repo *mocks.RepositoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(v1beta1.Version, mock.Anything, mock.Anything).Return(&mocks.RuleMock{}, nil)
				repo.EXPECT().AddRuleSet(mock.Anything, mock.Anything, mock.Anything).Return(errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"successful": {
			ruleset: &v1beta1.RuleSet{
				MetaData: common.MetaData{Source: "test"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(t *testing.T, mhf *mocks.FactoryMock, repo *mocks.RepositoryMock) {
				t.Helper()

				rul := &mocks.RuleMock{}

				mhf.EXPECT().CreateRule(v1beta1.Version, mock.Anything, mock.Anything).Return(rul, nil)
				repo.EXPECT().AddRuleSet(mock.Anything, "test", mock.MatchedBy(func(rules []rule.Rule) bool {
					return len(rules) == 1 && rules[0] == rul
				})).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			factory := mocks.NewFactoryMock(t)
			repo := mocks.NewRepositoryMock(t)

			tc.configure(t, factory, repo)

			processor := NewRuleSetProcessor(repo, factory, config.DecisionMode)

			// WHEN
			err := processor.OnCreated(t.Context(), tc.ruleset)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestRuleSetProcessorOnUpdated(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ruleset   *v1beta1.RuleSet
		configure func(t *testing.T, mhf *mocks.FactoryMock, repo *mocks.RepositoryMock)
		assert    func(t *testing.T, err error)
	}{
		"unsupported version": {
			ruleset: &v1beta1.RuleSet{Version: "foo"},
			configure: func(t *testing.T, _ *mocks.FactoryMock, _ *mocks.RepositoryMock) {
				t.Helper()
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedRuleSetVersion)
			},
		},
		"error while loading rule set": {
			ruleset: &v1beta1.RuleSet{Version: v1beta1.Version, Rules: []v1beta1.Rule{{ID: "foo"}}},
			configure: func(t *testing.T, mhf *mocks.FactoryMock, _ *mocks.RepositoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "loading rule ID='foo' failed")
			},
		},
		"error while updating rule set": {
			ruleset: &v1beta1.RuleSet{Version: v1beta1.Version, Rules: []v1beta1.Rule{{ID: "foo"}}},
			configure: func(t *testing.T, mhf *mocks.FactoryMock, repo *mocks.RepositoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(mock.Anything, mock.Anything, mock.Anything).Return(&mocks.RuleMock{}, nil)
				repo.EXPECT().UpdateRuleSet(mock.Anything, mock.Anything, mock.Anything).Return(errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"successful": {
			ruleset: &v1beta1.RuleSet{
				MetaData: common.MetaData{Source: "test"},
				Version:  v1beta1.Version,
				Name:     "foobar",
				Rules:    []v1beta1.Rule{{ID: "foo"}},
			},
			configure: func(t *testing.T, mhf *mocks.FactoryMock, repo *mocks.RepositoryMock) {
				t.Helper()

				rul := &mocks.RuleMock{}

				mhf.EXPECT().CreateRule(v1beta1.Version, mock.Anything, mock.Anything).Return(rul, nil)
				repo.EXPECT().UpdateRuleSet(mock.Anything, "test", mock.MatchedBy(func(rules []rule.Rule) bool {
					return len(rules) == 1 && rules[0] == rul
				})).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEM
			factory := mocks.NewFactoryMock(t)
			repo := mocks.NewRepositoryMock(t)

			tc.configure(t, factory, repo)

			processor := NewRuleSetProcessor(repo, factory, config.ProxyMode)

			// WHEN
			err := processor.OnUpdated(t.Context(), tc.ruleset)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestRuleSetProcessorOnDeleted(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ruleset   *v1beta1.RuleSet
		configure func(t *testing.T, repo *mocks.RepositoryMock)
		assert    func(t *testing.T, err error)
	}{
		"failed removing rule set": {
			ruleset: &v1beta1.RuleSet{
				MetaData: common.MetaData{Source: "test"},
				Version:  v1beta1.Version,
				Name:     "foobar",
			},
			configure: func(t *testing.T, repo *mocks.RepositoryMock) {
				t.Helper()

				repo.EXPECT().DeleteRuleSet(t.Context(), "test").Return(errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"successful": {
			ruleset: &v1beta1.RuleSet{
				MetaData: common.MetaData{Source: "test"},
				Version:  v1beta1.Version,
				Name:     "foobar",
			},
			configure: func(t *testing.T, repo *mocks.RepositoryMock) {
				t.Helper()

				repo.EXPECT().DeleteRuleSet(t.Context(), "test").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEM
			repo := mocks.NewRepositoryMock(t)
			tc.configure(t, repo)

			processor := NewRuleSetProcessor(repo, mocks.NewFactoryMock(t), config.DecisionMode)

			// WHEN
			err := processor.OnDeleted(t.Context(), tc.ruleset)

			// THEN
			tc.assert(t, err)
		})
	}
}
