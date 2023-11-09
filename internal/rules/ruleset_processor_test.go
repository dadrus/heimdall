// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestRuleSetProcessorOnCreated(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		ruleset          *config.RuleSet
		configureFactory func(t *testing.T, mhf *mocks.FactoryMock)
		assert           func(t *testing.T, err error, queue event.RuleSetChangedEventQueue)
	}{
		{
			uc:      "unsupported version",
			ruleset: &config.RuleSet{Version: "foo"},
			assert: func(t *testing.T, err error, _ event.RuleSetChangedEventQueue) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedRuleSetVersion)
			},
		},
		{
			uc:      "error while loading rule set",
			ruleset: &config.RuleSet{Version: config.CurrentRuleSetVersion, Rules: []config.Rule{{ID: "foo"}}},
			configureFactory: func(t *testing.T, mhf *mocks.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, testsupport.ErrTestPurpose)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		{
			uc: "successful",
			ruleset: &config.RuleSet{
				MetaData: config.MetaData{Source: "test"},
				Version:  config.CurrentRuleSetVersion,
				Name:     "foobar",
				Rules:    []config.Rule{{ID: "foo"}},
			},
			configureFactory: func(t *testing.T, mhf *mocks.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(config.CurrentRuleSetVersion, mock.Anything, mock.Anything).Return(&mocks.RuleMock{}, nil)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, queue, 1)

				evt := <-queue
				require.Len(t, evt.Rules, 1)
				assert.Equal(t, event.Create, evt.ChangeType)
				assert.Equal(t, "test", evt.Source)
				assert.Equal(t, "foobar", evt.Name)

				assert.Equal(t, &mocks.RuleMock{}, evt.Rules[0])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEM
			configureFactory := x.IfThenElse(tc.configureFactory != nil,
				tc.configureFactory,
				func(t *testing.T, mhf *mocks.FactoryMock) { t.Helper() })

			queue := make(event.RuleSetChangedEventQueue, 10)

			factory := mocks.NewFactoryMock(t)
			configureFactory(t, factory)

			processor := NewRuleSetProcessor(queue, factory, log.Logger)

			// WHEN
			err := processor.OnCreated(tc.ruleset)

			// THEN
			tc.assert(t, err, queue)
		})
	}
}

func TestRuleSetProcessorOnUpdated(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		ruleset          *config.RuleSet
		configureFactory func(t *testing.T, mhf *mocks.FactoryMock)
		assert           func(t *testing.T, err error, queue event.RuleSetChangedEventQueue)
	}{
		{
			uc:      "unsupported version",
			ruleset: &config.RuleSet{Version: "foo"},
			assert: func(t *testing.T, err error, _ event.RuleSetChangedEventQueue) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedRuleSetVersion)
			},
		},
		{
			uc:      "error while loading rule set",
			ruleset: &config.RuleSet{Version: config.CurrentRuleSetVersion, Rules: []config.Rule{{ID: "foo"}}},
			configureFactory: func(t *testing.T, mhf *mocks.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(mock.Anything, mock.Anything, mock.Anything).
					Return(nil, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, testsupport.ErrTestPurpose)
				assert.Contains(t, err.Error(), "failed loading")
			},
		},
		{
			uc: "successful",
			ruleset: &config.RuleSet{
				MetaData: config.MetaData{Source: "test"},
				Version:  config.CurrentRuleSetVersion,
				Name:     "foobar",
				Rules:    []config.Rule{{ID: "foo"}},
			},
			configureFactory: func(t *testing.T, mhf *mocks.FactoryMock) {
				t.Helper()

				mhf.EXPECT().CreateRule(config.CurrentRuleSetVersion, mock.Anything, mock.Anything).
					Return(&mocks.RuleMock{}, nil)
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, queue, 1)

				evt := <-queue
				require.Len(t, evt.Rules, 1)
				assert.Equal(t, event.Update, evt.ChangeType)
				assert.Equal(t, "test", evt.Source)
				assert.Equal(t, "foobar", evt.Name)

				assert.Equal(t, &mocks.RuleMock{}, evt.Rules[0])
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEM
			configureFactory := x.IfThenElse(tc.configureFactory != nil,
				tc.configureFactory,
				func(t *testing.T, mhf *mocks.FactoryMock) { t.Helper() })

			queue := make(event.RuleSetChangedEventQueue, 10)

			factory := mocks.NewFactoryMock(t)
			configureFactory(t, factory)

			processor := NewRuleSetProcessor(queue, factory, log.Logger)

			// WHEN
			err := processor.OnUpdated(tc.ruleset)

			// THEN
			tc.assert(t, err, queue)
		})
	}
}

func TestRuleSetProcessorOnDeleted(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		ruleset *config.RuleSet
		assert  func(t *testing.T, err error, queue event.RuleSetChangedEventQueue)
	}{
		{
			uc: "successful",
			ruleset: &config.RuleSet{
				MetaData: config.MetaData{Source: "test"},
				Version:  config.CurrentRuleSetVersion,
				Name:     "foobar",
			},
			assert: func(t *testing.T, err error, queue event.RuleSetChangedEventQueue) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, queue, 1)

				evt := <-queue
				assert.Equal(t, event.Remove, evt.ChangeType)
				assert.Equal(t, "test", evt.Source)
				assert.Equal(t, "foobar", evt.Name)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEM
			queue := make(event.RuleSetChangedEventQueue, 10)
			processor := NewRuleSetProcessor(queue, mocks.NewFactoryMock(t), log.Logger)

			// WHEN
			err := processor.OnDeleted(tc.ruleset)

			// THEN
			tc.assert(t, err, queue)
		})
	}
}
