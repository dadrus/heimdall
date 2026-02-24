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
	"errors"
	"net/url"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	mocks1 "github.com/dadrus/heimdall/internal/rules/mechanisms/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/pointer"
)

func TestRuleFactoryNew(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config                   *config.Configuration
		enforceSecureDefaultRule bool
		configureMocks           func(t *testing.T, repo *mocks1.RepositoryMock)
		assert                   func(t *testing.T, err error, f *ruleFactory)
	}{
		"new factory without default rule": {
			config: &config.Configuration{},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, ruleFactory)
				assert.Nil(t, ruleFactory.DefaultRule())
			},
		},
		"new factory with default rule with unsupported object in execute definition": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"foo": "bar"},
					},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unknown mechanism kind")
			},
		},
		"new factory with default rule with unsupported object in error handler definition": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					ErrorHandler: []config.MechanismConfig{
						{"foo": "bar"},
					},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unknown mechanism kind")
			},
		},
		"new factory with malformed default rule, where authenticator loading happens after identity handlers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"contextualizer": "bar", "id": "baz"},
						{"authenticator": "foo", "id": "zab"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "baz", Principal: "default"}).Return(nil, nil)

				repo.EXPECT().Contextualizer("bar").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "zab authenticator is defined after")
			},
		},
		"new factory with malformed default rule, where authenticator loading happens after finalizers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar", "id": "baz"},
						{"authenticator": "foo", "id": "zab"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "baz", Principal: "default"}).Return(nil, nil)

				repo.EXPECT().Finalizer("bar").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "zab authenticator is defined after")
			},
		},
		"new factory with default rule, where authenticator loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authenticator": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(nil, errors.New("test error"))

				repo.EXPECT().Authenticator("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with malformed default rule, where authorizer loading happens after finalizers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar"},
						{"authorizer": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(nil, nil)

				repo.EXPECT().Finalizer("bar").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "authorizer is defined after")
			},
		},
		"new factory with default rule, where authorizer loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"authorizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(nil, errors.New("test error"))

				repo.EXPECT().Authorizer("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with malformed default rule, where contextualizer loading happens after finalizers": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"finalizer": "bar"},
						{"contextualizer": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(nil, nil)

				repo.EXPECT().Finalizer("bar").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "contextualizer is defined after")
			},
		},
		"new factory with default rule, where contextualizer loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"contextualizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(nil, errors.New("test error"))

				repo.EXPECT().Contextualizer("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with default rule, where finalizer loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{{"finalizer": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(nil, errors.New("test error"))

				repo.EXPECT().Finalizer("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with default rule, where error_handler loading results in an error": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					ErrorHandler: []config.MechanismConfig{{"error_handler": "foo"}},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{}).Return(nil, errors.New("test error"))

				repo.EXPECT().ErrorHandler("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "test error")
			},
		},
		"new factory with empty default rule": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no authenticator")
			},
		},
		"new factory with insecure default rule, but enforced security settings": {
			enforceSecureDefaultRule: true,
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				insecure := mocks.NewInsecureMock(t)
				insecure.EXPECT().IsInsecure().Return(true)

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitInsecure(insecure)
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				repo.EXPECT().Authenticator("bar").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "insecure default rule")
			},
		},
		"new factory with default rule which does not define an authenticator for the default principal": {
			enforceSecureDefaultRule: true,
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar", "principal": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("foo")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "foo"}).Return(as, nil)

				repo.EXPECT().Authenticator("bar").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleFactory) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "default principal")
			},
		},
		"new factory with not security enforced default rule, configured with all required elements": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar", "id": "foo"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "foo", Principal: "default"}).Return(as, nil)

				repo.EXPECT().Authenticator("bar").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleFactory)
				assert.NotNil(t, ruleFactory.DefaultRule())
				assert.Equal(t, ruleFactory.defaultRule, ruleFactory.DefaultRule())

				defRule := ruleFactory.defaultRule
				assert.True(t, defRule.isDefault)
				assert.Equal(t, "default", defRule.id)
				assert.Equal(t, "config", defRule.srcID)
				assert.Equal(t, v1beta1.EncodedSlashesOff, defRule.slashesHandling)
				assert.Len(t, defRule.sc, 1)
				assert.Empty(t, defRule.sh)
				assert.Empty(t, defRule.fi)
				assert.Empty(t, defRule.eh)
			},
		},
		"new factory with default rule, configured with all possible elements": {
			config: &config.Configuration{
				Default: &config.DefaultRule{
					Execute: []config.MechanismConfig{
						{"authenticator": "bar", "id": "1"},
						{"contextualizer": "foo", "id": "2"},
						{"authorizer": "zab", "id": "3"},
						{"finalizer": "baz", "id": "4"},
					},
					ErrorHandler: []config.MechanismConfig{
						{"error_handler": "foobar", "id": "1"},
						{"error_handler": "barfoo", "id": "2"},
					},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1", Principal: "default"}).Return(as, nil)

				cont := mocks1.NewMechanismMock(t)
				cont.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "2", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				authz := mocks1.NewMechanismMock(t)
				authz.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "3", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				fin := mocks1.NewMechanismMock(t)
				fin.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "4", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				eh1 := mocks1.NewMechanismMock(t)
				eh1.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1"}).Return(mocks.NewStepMock(t), nil)

				eh2 := mocks1.NewMechanismMock(t)
				eh2.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "2"}).Return(mocks.NewStepMock(t), nil)

				repo.EXPECT().Authenticator("bar").Return(authn, nil)
				repo.EXPECT().Finalizer("baz").Return(fin, nil)
				repo.EXPECT().Authorizer("zab").Return(authz, nil)
				repo.EXPECT().Contextualizer("foo").Return(cont, nil)
				repo.EXPECT().ErrorHandler("foobar").Return(eh1, nil)
				repo.EXPECT().ErrorHandler("barfoo").Return(eh2, nil)
			},
			assert: func(t *testing.T, err error, ruleFactory *ruleFactory) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, ruleFactory)
				assert.NotNil(t, ruleFactory.DefaultRule())
				assert.Equal(t, ruleFactory.defaultRule, ruleFactory.DefaultRule())

				defRule := ruleFactory.defaultRule
				assert.True(t, defRule.isDefault)
				assert.Equal(t, "default", defRule.id)
				assert.Equal(t, "config", defRule.srcID)
				assert.Equal(t, v1beta1.EncodedSlashesOff, defRule.slashesHandling)
				assert.Len(t, defRule.sc, 1)
				assert.Len(t, defRule.sh, 2)
				assert.Len(t, defRule.fi, 1)
				assert.Len(t, defRule.eh, 2)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks1.RepositoryMock) { t.Helper() })

			repo := mocks1.NewRepositoryMock(t)
			configureMocks(t, repo)

			tp := otel.GetTracerProvider()

			// WHEN
			factory, err := NewRuleFactory(
				repo,
				tc.config,
				config.DecisionMode,
				log.Logger,
				tp.Tracer("test"),
				config.SecureDefaultRule(tc.enforceSecureDefaultRule),
			)

			// THEN
			impl, ok := factory.(*ruleFactory)
			if err == nil {
				require.True(t, ok)
			}

			// THEN
			tc.assert(t, err, impl)
		})
	}
}

func TestRuleFactoryCreateRule(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opMode         config.OperationMode
		config         v1beta1.Rule
		defaultRule    *ruleImpl
		configureMocks func(t *testing.T, repo *mocks1.RepositoryMock)
		assert         func(t *testing.T, err error, rul *ruleImpl)
	}{
		"in proxy mode without forward_to definition": {
			opMode: config.ProxyMode,
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "requires forward_to")
			},
		},
		"error while creating method matcher": {
			config: v1beta1.Rule{
				ID: "foobar",
				Matcher: v1beta1.Matcher{
					Routes:  []v1beta1.Route{{Path: "/foo/bar"}},
					Methods: []string{""},
				},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				repo.EXPECT().Authenticator("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "methods list contains empty values")
			},
		},
		"error while creating route path params matcher": {
			config: v1beta1.Rule{
				ID: "foobar",
				Matcher: v1beta1.Matcher{
					Routes: []v1beta1.Route{
						{
							Path:       "/foo/:bar",
							PathParams: []v1beta1.ParameterMatcher{{Name: "bar", Type: "foo", Value: "baz"}},
						},
					},
				},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo", ID: "1"},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1", Principal: "default"}).Return(as, nil)

				repo.EXPECT().Authenticator("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "failed creating route '/foo/:bar'")
			},
		},
		"error while creating the execute pipeline": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{{AuthenticatorRef: "foo"}},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(nil, errors.New("test error"))

				repo.EXPECT().Authenticator("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorContains(t, err, "test error")
			},
		},
		"error while creating on_error pipeline": {
			config: v1beta1.Rule{
				ID:           "foobar",
				Matcher:      v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				ErrorHandler: []v1beta1.Step{{ErrorHandlerRef: "foo", ID: "bar"}},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "bar"}).Return(nil, errors.New("test error"))

				repo.EXPECT().ErrorHandler("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorContains(t, err, "test error")
			},
		},
		"without default rule and without any execute configuration": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "no authenticator defined")
			},
		},
		"without default rule and with malformed execute configuration": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: ""},
				},
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported configuration")
			},
		},
		"without default rule and with malformed on_error configuration": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
				},
				ErrorHandler: []v1beta1.Step{
					{ErrorHandlerRef: ""},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				repo.EXPECT().Authenticator("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "unsupported configuration")
			},
		},
		"without default rule and minimum required configuration in decision mode": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
				},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				repo.EXPECT().Authenticator("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, v1beta1.EncodedSlashesOff, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())
				assert.Len(t, rul.sc, 1)
				assert.Empty(t, rul.sh)
				assert.Empty(t, rul.fi)
				assert.Empty(t, rul.eh)
			},
		},
		"without default rule and minimum required configuration in proxy mode": {
			opMode: config.ProxyMode,
			config: v1beta1.Rule{
				ID:      "foobar",
				Backend: &v1beta1.Backend{Host: "foo.bar"},
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{{AuthenticatorRef: "foo"}},
			},
			configureMocks: func(t *testing.T, repo *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				mechanism := mocks1.NewMechanismMock(t)
				mechanism.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				repo.EXPECT().Authenticator("foo").Return(mechanism, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, v1beta1.EncodedSlashesOff, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())
				assert.Len(t, rul.sc, 1)
				assert.Empty(t, rul.sh)
				assert.Empty(t, rul.fi)
				assert.Empty(t, rul.eh)
				assert.NotNil(t, rul.backend)
			},
		},
		"with default rule and regular rule with id and a single route only": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
			},
			defaultRule: &ruleImpl{
				sc: stage{func() step {
					as := &mocks.StepMock{}
					as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
						pn := mocks.NewPrincipalNamerMock(t)
						pn.EXPECT().PrincipalName().Return("default")

						visitor.VisitPrincipalNamer(pn)

						return true
					}))

					return as
				}()},
				sh: stage{mocks.NewStepMock(t)},
				fi: stage{mocks.NewStepMock(t)},
				eh: stage{mocks.NewStepMock(t)},
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())
				assert.Len(t, rul.sc, 1)
				assert.Len(t, rul.sh, 1)
				assert.Len(t, rul.fi, 1)
				assert.Len(t, rul.eh, 1)
			},
		},
		"with default rule and with all attributes defined by the regular rule itself in decision mode": {
			config: v1beta1.Rule{
				ID: "foobar",
				Matcher: v1beta1.Matcher{
					Routes: []v1beta1.Route{
						{
							Path:       "/foo/:resource",
							PathParams: []v1beta1.ParameterMatcher{{Name: "resource", Type: "regex", Value: "(bar|baz)"}},
						},
						{
							Path:       "/bar/:resource",
							PathParams: []v1beta1.ParameterMatcher{{Name: "resource", Type: "glob", Value: "{a,b}"}},
						},
					},
					Scheme:  "https",
					Methods: []string{"BAR", "BAZ"},
					Hosts:   []string{"*.example.com"},
				},
				EncodedSlashesHandling: v1beta1.EncodedSlashesOnNoDecode,
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo", ID: "1"},
					{ContextualizerRef: "bar", ID: "2"},
					{AuthorizerRef: "zab", ID: "3"},
					{FinalizerRef: "baz", ID: "4"},
				},
				ErrorHandler: []v1beta1.Step{
					{ErrorHandlerRef: "foo", ID: "5"},
				},
			},
			defaultRule: &ruleImpl{
				sc: stage{mocks.NewStepMock(t)},
				sh: stage{mocks.NewStepMock(t)},
				fi: stage{mocks.NewStepMock(t)},
				eh: stage{mocks.NewStepMock(t)},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1", Principal: "default"}).Return(as, nil)

				cont := mocks1.NewMechanismMock(t)
				cont.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "2", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				authz := mocks1.NewMechanismMock(t)
				authz.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "3", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				fin := mocks1.NewMechanismMock(t)
				fin.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "4", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				eh := mocks1.NewMechanismMock(t)
				eh.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "5"}).Return(mocks.NewStepMock(t), nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().Contextualizer("bar").Return(cont, nil)
				mhf.EXPECT().Authorizer("zab").Return(authz, nil)
				mhf.EXPECT().Finalizer("baz").Return(fin, nil)
				mhf.EXPECT().ErrorHandler("foo").Return(eh, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, v1beta1.EncodedSlashesOnNoDecode, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 2)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/:resource", rul.Routes()[0].Path())
				assert.Equal(t, rul, rul.Routes()[1].Rule())
				assert.Equal(t, "/bar/:resource", rul.Routes()[1].Path())

				// nil checks above mean the responses from the mockHandlerFactory are used
				// and not the values from the default rule
				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])
				require.Len(t, rul.sh, 2)
				assert.NotNil(t, rul.sh[0])
				assert.NotNil(t, rul.sh[1])
				require.Len(t, rul.fi, 1)
				assert.NotNil(t, rul.fi[0])
				require.Len(t, rul.eh, 1)
				assert.NotNil(t, rul.eh[0])
			},
		},
		"with default rule and with all attributes defined by the rule itself in proxy mode": {
			opMode: config.ProxyMode,
			config: v1beta1.Rule{
				ID: "foobar",
				Matcher: v1beta1.Matcher{
					Routes: []v1beta1.Route{
						{
							Path:       "/foo/:resource",
							PathParams: []v1beta1.ParameterMatcher{{Name: "resource", Type: "regex", Value: "(bar|baz)"}},
						},
						{
							Path:       "/bar/:resource",
							PathParams: []v1beta1.ParameterMatcher{{Name: "resource", Type: "glob", Value: "{a,b}"}},
						},
					},
					Scheme:  "https",
					Methods: []string{"BAR", "BAZ"},
					Hosts:   []string{"*.example.com"},
				},
				EncodedSlashesHandling: v1beta1.EncodedSlashesOn,
				Backend: &v1beta1.Backend{
					Host: "bar.foo",
					URLRewriter: &v1beta1.URLRewriter{
						Scheme:              "https",
						PathPrefixToCut:     "/foo",
						PathPrefixToAdd:     "/baz",
						QueryParamsToRemove: []string{"bar"},
					},
				},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo", ID: "1"},
					{ContextualizerRef: "bar", ID: "2"},
					{AuthorizerRef: "zab", ID: "3"},
					{FinalizerRef: "baz", ID: "false"},
				},
				ErrorHandler: []v1beta1.Step{
					{ErrorHandlerRef: "foo", ID: "true"},
				},
			},
			defaultRule: &ruleImpl{
				sc: stage{mocks.NewStepMock(t)},
				sh: stage{mocks.NewStepMock(t)},
				fi: stage{mocks.NewStepMock(t)},
				eh: stage{mocks.NewStepMock(t)},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1", Principal: "default"}).Return(as, nil)

				cont := mocks1.NewMechanismMock(t)
				cont.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "2", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				authz := mocks1.NewMechanismMock(t)
				authz.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "3", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				fin := mocks1.NewMechanismMock(t)
				fin.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "false", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				eh := mocks1.NewMechanismMock(t)
				eh.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "true"}).Return(mocks.NewStepMock(t), nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().Contextualizer("bar").Return(cont, nil)
				mhf.EXPECT().Authorizer("zab").Return(authz, nil)
				mhf.EXPECT().Finalizer("baz").Return(fin, nil)
				mhf.EXPECT().ErrorHandler("foo").Return(eh, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Equal(t, v1beta1.EncodedSlashesOn, rul.slashesHandling)
				assert.Len(t, rul.Routes(), 2)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/:resource", rul.Routes()[0].Path())
				assert.Equal(t, rul, rul.Routes()[1].Rule())
				assert.Equal(t, "/bar/:resource", rul.Routes()[1].Path())
				assert.Equal(t, "https://bar.foo/baz/bar?foo=bar", rul.backend.CreateURL(&url.URL{
					Scheme:   "http",
					Host:     "foo.bar:8888",
					Path:     "/foo/bar",
					RawQuery: url.Values{"bar": []string{"foo"}, "foo": []string{"bar"}}.Encode(),
				}).String())

				// nil checks above mean the responses from the mockHandlerFactory are used
				// and not the values from the default rule
				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])
				require.Len(t, rul.sh, 2)
				assert.NotNil(t, rul.sh[0])
				assert.NotNil(t, rul.sh[1])
				require.Len(t, rul.fi, 1)
				assert.NotNil(t, rul.fi[0])
				require.Len(t, rul.eh, 1)
				assert.NotNil(t, rul.eh[0])
				assert.NotNil(t, rul.backend)
			},
		},
		"malformed conditional configuration in the execute pipeline": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
					{FinalizerRef: "bar", Condition: pointer.To("")},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				fin := mocks1.NewMechanismMock(t)
				fin.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().Finalizer("bar").Return(fin, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "empty cel expression")
			},
		},
		"duplicate step ids in the execute pipeline": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo", ID: "1"},
					{FinalizerRef: "bar", ID: "1"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				fin := mocks1.NewMechanismMock(t)
				fin.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1", Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().Finalizer("bar").Return(fin, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "must be unique")
			},
		},
		"conditional execution of some mechanisms in the execute pipeline": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
					{AuthorizerRef: "bar", Condition: pointer.To("false")},
					{ContextualizerRef: "bar", Condition: pointer.To("true")},
					{AuthorizerRef: "baz"},
					{FinalizerRef: "bar", Condition: pointer.To("true")},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				authz := mocks1.NewMechanismMock(t)
				authz.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				cont := mocks1.NewMechanismMock(t)
				cont.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				fin := mocks1.NewMechanismMock(t)
				fin.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().Authorizer(mock.Anything).Return(authz, nil).Times(2)
				mhf.EXPECT().Contextualizer("bar").Return(cont, nil)
				mhf.EXPECT().Finalizer("bar").Return(fin, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())

				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])

				require.Len(t, rul.sh, 3)

				assert.NotNil(t, rul.sh[0])
				sh, ok := rul.sh[0].(*conditionalStep)
				require.True(t, ok)
				assert.IsType(t, &celExecutionCondition{}, sh.c)

				assert.NotNil(t, rul.sh[1])
				sh, ok = rul.sh[1].(*conditionalStep)
				require.True(t, ok)
				assert.IsType(t, &celExecutionCondition{}, sh.c)

				assert.NotNil(t, rul.sh[2])
				_, ok = rul.sh[2].(*conditionalStep)
				require.False(t, ok)

				require.Len(t, rul.fi, 1)
				un, ok := rul.fi[0].(*conditionalStep)
				require.True(t, ok)
				assert.IsType(t, &celExecutionCondition{}, un.c)

				require.Empty(t, rul.eh)
			},
		},
		"conditional execution of error handler": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
					{AuthorizerRef: "bar"},
					{FinalizerRef: "baz"},
				},
				ErrorHandler: []v1beta1.Step{
					{ErrorHandlerRef: "foo", Condition: pointer.To("true")},
					{ErrorHandlerRef: "bar", Condition: pointer.To("false")},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				authz := mocks1.NewMechanismMock(t)
				authz.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				fin := mocks1.NewMechanismMock(t)
				fin.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				eh1 := mocks1.NewMechanismMock(t)
				eh1.EXPECT().CreateStep(mechanisms.StepDefinition{}).Return(mocks.NewStepMock(t), nil)

				eh2 := mocks1.NewMechanismMock(t)
				eh2.EXPECT().CreateStep(mechanisms.StepDefinition{}).Return(mocks.NewStepMock(t), nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().Authorizer("bar").Return(authz, nil)
				mhf.EXPECT().Finalizer("baz").Return(fin, nil)
				mhf.EXPECT().ErrorHandler("foo").Return(eh1, nil)
				mhf.EXPECT().ErrorHandler("bar").Return(eh2, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())

				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])

				require.Len(t, rul.sh, 1)

				assert.NotNil(t, rul.sh[0])
				_, ok := rul.sh[0].(*conditionalStep)
				require.False(t, ok)

				require.Len(t, rul.fi, 1)
				_, ok = rul.fi[0].(*conditionalStep)
				require.False(t, ok)

				require.Len(t, rul.eh, 2)
				_, ok = rul.eh[0].(*conditionalStep)
				require.True(t, ok)
				_, ok = rul.eh[1].(*conditionalStep)
				require.True(t, ok)
			},
		},
		"duplicate ids in the error pipeline": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
				},
				ErrorHandler: []v1beta1.Step{
					{ErrorHandlerRef: "foo", ID: "1"},
					{ErrorHandlerRef: "bar", ID: "1"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(mocks.NewStepMock(t), nil)

				eh1 := mocks1.NewMechanismMock(t)
				eh1.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1"}).Return(mocks.NewStepMock(t), nil)

				eh2 := mocks1.NewMechanismMock(t)
				eh2.EXPECT().CreateStep(mechanisms.StepDefinition{ID: "1"}).Return(mocks.NewStepMock(t), nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().ErrorHandler("foo").Return(eh1, nil)
				mhf.EXPECT().ErrorHandler("bar").Return(eh2, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "must be unique")
			},
		},
		"error while getting the referenced mechanism": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				mhf.EXPECT().Authenticator("foo").Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrStepCreation)
				require.ErrorContains(t, err, "test error")
			},
		},
		"fallback of authenticators for the default principal": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
					{AuthenticatorRef: "bar"},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				pn := mocks.NewPrincipalNamerMock(t)
				pn.EXPECT().PrincipalName().Return("default")

				as := mocks.NewStepMock(t)
				as.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn)

					return true
				}))

				authn := mocks1.NewMechanismMock(t)
				authn.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as, nil)

				mhf.EXPECT().Authenticator("foo").Return(authn, nil)
				mhf.EXPECT().Authenticator("bar").Return(authn, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())

				require.Len(t, rul.sc, 1)
				assert.NotNil(t, rul.sc[0])
				require.Len(t, rul.sc[0], 2)
			},
		},
		"single authenticator for the default principal and fallback authenticators for custom named principal": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "foo"},
					{AuthenticatorRef: "bar", Principal: pointer.To("custom")},
					{AuthenticatorRef: "baz", Principal: pointer.To("custom")},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				pn1 := mocks.NewPrincipalNamerMock(t)
				pn1.EXPECT().PrincipalName().Return("default")

				as1 := mocks.NewStepMock(t)
				as1.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn1)

					return true
				}))

				pn2 := mocks.NewPrincipalNamerMock(t)
				pn2.EXPECT().PrincipalName().Return("custom")

				as2 := mocks.NewStepMock(t)
				as2.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn2)

					return true
				}))

				authn1 := mocks1.NewMechanismMock(t)
				authn1.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "default"}).Return(as1, nil)

				authn2 := mocks1.NewMechanismMock(t)
				authn2.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "custom"}).Return(as2, nil)

				authn3 := mocks1.NewMechanismMock(t)
				authn3.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "custom"}).Return(as2, nil)

				mhf.EXPECT().Authenticator("foo").Return(authn1, nil)
				mhf.EXPECT().Authenticator("bar").Return(authn2, nil)
				mhf.EXPECT().Authenticator("baz").Return(authn3, nil)
			},
			assert: func(t *testing.T, err error, rul *ruleImpl) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, rul)

				assert.Equal(t, "test", rul.srcID)
				assert.False(t, rul.isDefault)
				assert.Equal(t, "foobar", rul.id)
				assert.Len(t, rul.Routes(), 1)
				assert.Equal(t, rul, rul.Routes()[0].Rule())
				assert.Equal(t, "/foo/bar", rul.Routes()[0].Path())

				require.Len(t, rul.sc, 2)
				assert.NotNil(t, rul.sc[0])
				require.Len(t, rul.sc[0], 1)
				assert.NotNil(t, rul.sc[1])
				require.Len(t, rul.sc[1], 2)
			},
		},
		"no authenticator for the default principal configured": {
			config: v1beta1.Rule{
				ID:      "foobar",
				Matcher: v1beta1.Matcher{Routes: []v1beta1.Route{{Path: "/foo/bar"}}},
				Execute: []v1beta1.Step{
					{AuthenticatorRef: "bar", Principal: pointer.To("a")},
					{AuthenticatorRef: "baz", Principal: pointer.To("b")},
				},
			},
			configureMocks: func(t *testing.T, mhf *mocks1.RepositoryMock) {
				t.Helper()

				pn1 := mocks.NewPrincipalNamerMock(t)
				pn1.EXPECT().PrincipalName().Return("a")

				as1 := mocks.NewStepMock(t)
				as1.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn1)

					return true
				}))

				pn2 := mocks.NewPrincipalNamerMock(t)
				pn2.EXPECT().PrincipalName().Return("b")

				as2 := mocks.NewStepMock(t)
				as2.EXPECT().Accept(mock.MatchedBy(func(visitor pipeline.Visitor) bool {
					visitor.VisitPrincipalNamer(pn2)

					return true
				}))

				authn1 := mocks1.NewMechanismMock(t)
				authn1.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "a"}).Return(as1, nil)

				authn2 := mocks1.NewMechanismMock(t)
				authn2.EXPECT().CreateStep(mechanisms.StepDefinition{Principal: "b"}).Return(as2, nil)

				mhf.EXPECT().Authenticator("bar").Return(authn1, nil)
				mhf.EXPECT().Authenticator("baz").Return(authn2, nil)
			},
			assert: func(t *testing.T, err error, _ *ruleImpl) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorContains(t, err, "default principal")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			configureMocks := x.IfThenElse(tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks1.RepositoryMock) { t.Helper() })

			repo := mocks1.NewRepositoryMock(t)
			configureMocks(t, repo)

			factory := &ruleFactory{
				r:              repo,
				defaultRule:    tc.defaultRule,
				mode:           tc.opMode,
				l:              log.Logger,
				hasDefaultRule: x.IfThenElse(tc.defaultRule != nil, true, false),
			}

			// WHEN
			rul, err := factory.CreateRule("test", tc.config)

			// THEN
			impl, ok := rul.(*ruleImpl)
			if err == nil {
				require.True(t, ok)
			}

			// THEN
			tc.assert(t, err, impl)
		})
	}
}
