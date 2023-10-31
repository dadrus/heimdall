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

package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha2"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
	mock2 "github.com/dadrus/heimdall/internal/x/testsupport/mock"
)

func TestNewProvider(t *testing.T) {
	// provider creates a client which registers its scheme
	// the corresponding k8s api is not threat safe.
	// So, to avoid concurrent map writes, this test is not configured
	// to run parallel
	for _, tc := range []struct {
		uc     string
		conf   []byte
		assert func(t *testing.T, err error, prov *provider)
	}{
		{
			uc:   "with unknown field",
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		{
			uc:   "with empty configuration",
			conf: []byte(`{}`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, DefaultClass, prov.ac)
				assert.Nil(t, prov.cancel)
				assert.NotNil(t, prov.cl)
			},
		},
		{
			uc:   "with auth_class configured",
			conf: []byte(`auth_class: foo`),
			assert: func(t *testing.T, err error, prov *provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "foo", prov.ac)
				assert.Nil(t, prov.cancel)
				assert.NotNil(t, prov.cl)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			conf := &config.Configuration{
				Rules: config.Rules{
					Providers: config.RuleProviders{Kubernetes: providerConf},
				},
			}
			k8sCF := func() (*rest.Config, error) { return &rest.Config{Host: "http://localhost:80001"}, nil }

			// WHEN
			prov, err := newProvider(log.Logger, conf, k8sCF, mocks.NewRuleSetProcessorMock(t), mocks.NewFactoryMock(t))

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

func TestProviderLifecycle(t *testing.T) {
	type (
		ResponseWriter func(t *testing.T, watchRequest bool, w http.ResponseWriter)
		StatusWriter   func(t *testing.T, r *http.Request, w http.ResponseWriter)

		StatusUpdate struct {
			Status v1alpha2.RuleSetStatus `json:"status"`
		}

		Observations struct {
			statusUpdates []*v1alpha2.RuleSetStatus
		}
	)

	var (
		writeResponse ResponseWriter
		writeStatus   StatusWriter
	)

	observations := &Observations{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			writeStatus(t, r, w)
		} else {
			writeResponse(t, r.URL.Query().Get("watch") == "true", w)
		}
	}))

	defer srv.Close()

	for _, tc := range []struct {
		uc             string
		conf           []byte
		writeResponse  ResponseWriter
		writeStatus    StatusWriter
		setupProcessor func(t *testing.T, processor *mocks.RuleSetProcessorMock)
		assert         func(t *testing.T, observation *Observations, processor *mocks.RuleSetProcessorMock)
	}{
		{
			uc:   "rule set added",
			conf: []byte("auth_class: bar"),
			writeResponse: func() ResponseWriter {
				callIdx := 0

				return func(t *testing.T, watchRequest bool, w http.ResponseWriter) {
					t.Helper()

					rls := v1alpha2.RuleSetList{
						TypeMeta: metav1.TypeMeta{
							APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
							Kind:       "RuleSetList",
						},
						ListMeta: metav1.ListMeta{
							ResourceVersion: "735820",
						},
						Items: []v1alpha2.RuleSet{
							{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									Name:              "test-rule",
									Namespace:         "foo",
									ResourceVersion:   "702666",
									UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
									Generation:        1,
									CreationTimestamp: metav1.NewTime(time.Now()),
								},
								Spec: v1alpha2.RuleSetSpec{
									AuthClassName: "bar",
									Rules: []config2.Rule{
										{
											ID: "test",
											RuleMatcher: config2.Matcher{
												URL:      "http://foo.bar",
												Strategy: "glob",
											},
											Backend: &config2.Backend{
												Host: "baz",
												URLRewriter: &config2.URLRewriter{
													Scheme:              "http",
													PathPrefixToCut:     "/foo",
													PathPrefixToAdd:     "/bar",
													QueryParamsToRemove: []string{"baz"},
												},
											},
											Methods: []string{http.MethodGet},
											Execute: []config.MechanismConfig{
												{"authenticator": "authn"},
												{"authorizer": "authz"},
											},
										},
									},
								},
							},
						},
					}

					rawRls, err := json.Marshal(rls)
					require.NoError(t, err)

					var evt metav1.WatchEvent

					err = metav1.Convert_watch_Event_To_v1_WatchEvent(
						&watch.Event{
							Type: watch.Bookmark,
							Object: &v1alpha2.RuleSet{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									ResourceVersion: "715382",
								},
							},
						},
						&evt, nil)
					require.NoError(t, err)

					rawEvt, err := json.Marshal(evt)
					require.NoError(t, err)

					w.Header().Set("Content-Type", "application/json")
					if watchRequest {
						if callIdx == 0 {
							_, err := w.Write(rawEvt)
							require.NoError(t, err)
						} else {
							time.Sleep(1 * time.Second)
							w.WriteHeader(http.StatusInternalServerError)
						}

						callIdx++
					} else {
						_, err := w.Write(rawRls)
						require.NoError(t, err)
					}
				}
			}(),
			writeStatus: func(t *testing.T, r *http.Request, w http.ResponseWriter) {
				t.Helper()

				status := StatusUpdate{}
				err := json.NewDecoder(r.Body).Decode(&status)
				require.NoError(t, err)

				observations.statusUpdates = append(observations.statusUpdates, &status.Status)

				rs := &v1alpha2.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702667",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha2.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								RuleMatcher: config2.Matcher{
									URL:      "http://foo.bar",
									Strategy: "glob",
								},
								Backend: &config2.Backend{
									Host: "baz",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Methods: []string{http.MethodGet},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}

				rs.Status = status.Status

				data, err := json.Marshal(rs)
				require.NoError(t, err)

				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, observation *Observations, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86")
				assert.Equal(t, "1alpha2", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				rule := ruleSet.Rules[0]
				assert.Equal(t, "test", rule.ID)
				assert.Equal(t, "http://foo.bar", rule.RuleMatcher.URL)
				assert.Equal(t, "baz", rule.Backend.Host)
				assert.Equal(t, "glob", rule.RuleMatcher.Strategy)
				assert.Len(t, rule.Methods, 1)
				assert.Contains(t, rule.Methods, http.MethodGet)
				assert.Empty(t, rule.ErrorHandler)
				assert.Len(t, rule.Execute, 2)
				assert.Equal(t, "authn", rule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", rule.Execute[1]["authorizer"])

				assert.Len(t, observation.statusUpdates, 1)
				assert.Len(t, observation.statusUpdates[0].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[0].UsedByInstances, 1)
				assert.Len(t, observation.statusUpdates[0].Conditions, 1)

				condition := observation.statusUpdates[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActive, v1alpha2.ConditionReason(condition.Reason))
			},
		},
		{
			uc:   "adding rule set fails",
			conf: []byte("auth_class: bar"),
			writeResponse: func() ResponseWriter {
				callIdx := 0

				return func(t *testing.T, watchRequest bool, w http.ResponseWriter) {
					t.Helper()

					rls := v1alpha2.RuleSetList{
						TypeMeta: metav1.TypeMeta{
							APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
							Kind:       "RuleSetList",
						},
						ListMeta: metav1.ListMeta{
							ResourceVersion: "735820",
						},
						Items: []v1alpha2.RuleSet{
							{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									Name:              "test-rule",
									Namespace:         "foo",
									ResourceVersion:   "702666",
									UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
									Generation:        1,
									CreationTimestamp: metav1.NewTime(time.Now()),
								},
								Spec: v1alpha2.RuleSetSpec{
									AuthClassName: "bar",
									Rules: []config2.Rule{
										{
											ID: "test",
											RuleMatcher: config2.Matcher{
												URL:      "http://foo.bar",
												Strategy: "glob",
											},
											Backend: &config2.Backend{
												Host: "bar",
												URLRewriter: &config2.URLRewriter{
													Scheme:              "http",
													PathPrefixToCut:     "/foo",
													PathPrefixToAdd:     "/bar",
													QueryParamsToRemove: []string{"baz"},
												},
											},
											Methods: []string{http.MethodGet},
											Execute: []config.MechanismConfig{
												{"authenticator": "authn"},
												{"authorizer": "authz"},
											},
										},
									},
								},
							},
						},
					}

					rawRls, err := json.Marshal(rls)
					require.NoError(t, err)

					var evt metav1.WatchEvent

					err = metav1.Convert_watch_Event_To_v1_WatchEvent(
						&watch.Event{
							Type: watch.Bookmark,
							Object: &v1alpha2.RuleSet{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									ResourceVersion: "715382",
								},
							},
						},
						&evt, nil)
					require.NoError(t, err)

					rawEvt, err := json.Marshal(evt)
					require.NoError(t, err)

					w.Header().Set("Content-Type", "application/json")
					if watchRequest {
						if callIdx == 0 {
							_, err := w.Write(rawEvt)
							require.NoError(t, err)
						} else {
							time.Sleep(1 * time.Second)
							w.WriteHeader(http.StatusInternalServerError)
						}

						callIdx++
					} else {
						_, err := w.Write(rawRls)
						require.NoError(t, err)
					}
				}
			}(),
			writeStatus: func(t *testing.T, r *http.Request, w http.ResponseWriter) {
				t.Helper()

				status := StatusUpdate{}
				err := json.NewDecoder(r.Body).Decode(&status)
				require.NoError(t, err)

				observations.statusUpdates = append(observations.statusUpdates, &status.Status)

				rs := v1alpha2.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702667",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha2.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								RuleMatcher: config2.Matcher{
									URL:      "http://foo.bar",
									Strategy: "glob",
								},
								Backend: &config2.Backend{
									Host: "bar",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Methods: []string{http.MethodGet},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}

				rs.Status = status.Status

				data, err := json.Marshal(rs)
				require.NoError(t, err)

				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).Return(testsupport.ErrTestPurpose).Once()
			},
			assert: func(t *testing.T, observation *Observations, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				assert.Len(t, observation.statusUpdates, 1)
				assert.Len(t, observation.statusUpdates[0].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[0].UsedByInstances, 0)
				assert.Len(t, observation.statusUpdates[0].Conditions, 1)

				condition := observation.statusUpdates[0].Conditions[0]
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActivationFailed, v1alpha2.ConditionReason(condition.Reason))
			},
		},
		{
			uc:   "a ruleset is added and then removed",
			conf: []byte("auth_class: bar"),
			writeResponse: func() ResponseWriter {
				callIdx := 0

				return func(t *testing.T, watchRequest bool, w http.ResponseWriter) {
					t.Helper()

					w.Header().Set("Content-Type", "application/json")
					if watchRequest {
						callIdx++

						evt := watch.Event{
							Type: watch.Added,
							Object: &v1alpha2.RuleSet{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									ResourceVersion:   "715382",
									Name:              "test-rule",
									Namespace:         "foo",
									UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
									Generation:        1,
									CreationTimestamp: metav1.NewTime(time.Now()),
								},
								Spec: v1alpha2.RuleSetSpec{
									AuthClassName: "bar",
									Rules: []config2.Rule{
										{
											ID: "test",
											RuleMatcher: config2.Matcher{
												URL:      "http://foo.bar",
												Strategy: "glob",
											},
											Backend: &config2.Backend{
												Host: "bar",
												URLRewriter: &config2.URLRewriter{
													Scheme:              "http",
													PathPrefixToCut:     "/foo",
													PathPrefixToAdd:     "/bar",
													QueryParamsToRemove: []string{"baz"},
												},
											},
											Methods: []string{http.MethodGet},
											Execute: []config.MechanismConfig{
												{"authenticator": "authn"},
												{"authorizer": "authz"},
											},
										},
									},
								},
							},
						}

						switch callIdx {
						case 1:
							// add a rule set
							var watchEvt metav1.WatchEvent

							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						case 2:
							// remove it
							var watchEvt metav1.WatchEvent

							evt.Type = watch.Deleted
							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						default:
							// no changes
							time.Sleep(1 * time.Second)
							w.WriteHeader(http.StatusInternalServerError)
						}
					} else {
						// empty rule set initially
						rls := v1alpha2.RuleSetList{
							TypeMeta: metav1.TypeMeta{
								APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
								Kind:       "RuleSetList",
							},
							ListMeta: metav1.ListMeta{
								ResourceVersion: "735820",
							},
						}

						rawRls, err := json.Marshal(rls)
						require.NoError(t, err)

						_, err = w.Write(rawRls)
						require.NoError(t, err)
					}
				}
			}(),
			writeStatus: func(t *testing.T, r *http.Request, w http.ResponseWriter) {
				t.Helper()

				status := StatusUpdate{}
				err := json.NewDecoder(r.Body).Decode(&status)
				require.NoError(t, err)

				observations.statusUpdates = append(observations.statusUpdates, &status.Status)

				rs := v1alpha2.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						ResourceVersion:   "715383",
						Name:              "test-rule",
						Namespace:         "foo",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha2.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								RuleMatcher: config2.Matcher{
									URL:      "http://foo.bar",
									Strategy: "glob",
								},
								Backend: &config2.Backend{
									Host: "bar",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Methods: []string{http.MethodGet},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}

				rs.Status = status.Status

				data, err := json.Marshal(rs)
				require.NoError(t, err)

				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()

				processor.EXPECT().OnDeleted(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, observation *Observations, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, ruleSet.Source, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86")
				assert.Equal(t, "1alpha2", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				createdRule := ruleSet.Rules[0]
				assert.Equal(t, "test", createdRule.ID)
				assert.Equal(t, "http://foo.bar", createdRule.RuleMatcher.URL)
				assert.Equal(t, "bar", createdRule.Backend.Host)
				assert.Equal(t, "glob", createdRule.RuleMatcher.Strategy)
				assert.Len(t, createdRule.Methods, 1)
				assert.Contains(t, createdRule.Methods, http.MethodGet)
				assert.Empty(t, createdRule.ErrorHandler)
				assert.Len(t, createdRule.Execute, 2)
				assert.Equal(t, "authn", createdRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", createdRule.Execute[1]["authorizer"])

				ruleSet = mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha2", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)

				assert.Len(t, observation.statusUpdates, 2)
				assert.Len(t, observation.statusUpdates[0].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[0].UsedByInstances, 1)
				assert.Len(t, observation.statusUpdates[0].Conditions, 1)
				condition := observation.statusUpdates[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActive, v1alpha2.ConditionReason(condition.Reason))

				assert.Len(t, observation.statusUpdates[1].MatchingInstances, 0)
				assert.Len(t, observation.statusUpdates[1].UsedByInstances, 0)
				assert.Len(t, observation.statusUpdates[1].Conditions, 1)
				condition = observation.statusUpdates[1].Conditions[0]
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetUnloaded, v1alpha2.ConditionReason(condition.Reason))
			},
		},
		{
			uc:   "removing rule set fails",
			conf: []byte("auth_class: bar"),
			writeResponse: func() ResponseWriter {
				callIdx := 0

				return func(t *testing.T, watchRequest bool, w http.ResponseWriter) {
					t.Helper()

					w.Header().Set("Content-Type", "application/json")
					if watchRequest {
						callIdx++

						evt := watch.Event{
							Type: watch.Added,
							Object: &v1alpha2.RuleSet{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									ResourceVersion:   "715382",
									Name:              "test-rule",
									Namespace:         "foo",
									UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
									Generation:        1,
									CreationTimestamp: metav1.NewTime(time.Now()),
								},
								Spec: v1alpha2.RuleSetSpec{
									AuthClassName: "bar",
									Rules: []config2.Rule{
										{
											ID: "test",
											RuleMatcher: config2.Matcher{
												URL:      "http://foo.bar",
												Strategy: "glob",
											},
											Backend: &config2.Backend{
												Host: "bar",
												URLRewriter: &config2.URLRewriter{
													Scheme:              "http",
													PathPrefixToCut:     "/foo",
													PathPrefixToAdd:     "/bar",
													QueryParamsToRemove: []string{"baz"},
												},
											},
											Methods: []string{http.MethodGet},
											Execute: []config.MechanismConfig{
												{"authenticator": "authn"},
												{"authorizer": "authz"},
											},
										},
									},
								},
							},
						}

						switch callIdx {
						case 1:
							// add a rule set
							var watchEvt metav1.WatchEvent

							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						case 2:
							// remove it
							var watchEvt metav1.WatchEvent

							evt.Type = watch.Deleted
							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						default:
							// no changes
							time.Sleep(1 * time.Second)
							w.WriteHeader(http.StatusInternalServerError)
						}
					} else {
						// empty rule set initially
						rls := v1alpha2.RuleSetList{
							TypeMeta: metav1.TypeMeta{
								APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
								Kind:       "RuleSetList",
							},
							ListMeta: metav1.ListMeta{
								ResourceVersion: "735820",
							},
						}

						rawRls, err := json.Marshal(rls)
						require.NoError(t, err)

						_, err = w.Write(rawRls)
						require.NoError(t, err)
					}
				}
			}(),
			writeStatus: func(t *testing.T, r *http.Request, w http.ResponseWriter) {
				t.Helper()

				status := StatusUpdate{}
				err := json.NewDecoder(r.Body).Decode(&status)
				require.NoError(t, err)

				observations.statusUpdates = append(observations.statusUpdates, &status.Status)

				rs := v1alpha2.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						ResourceVersion:   "715383",
						Name:              "test-rule",
						Namespace:         "foo",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha2.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								RuleMatcher: config2.Matcher{
									URL:      "http://foo.bar",
									Strategy: "glob",
								},
								Backend: &config2.Backend{
									Host: "bar",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Methods: []string{http.MethodGet},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}

				rs.Status = status.Status

				data, err := json.Marshal(rs)
				require.NoError(t, err)

				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).Return(nil).Once()
				processor.EXPECT().OnDeleted(mock.Anything).Return(testsupport.ErrTestPurpose).Once()
			},
			assert: func(t *testing.T, observation *Observations, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				assert.Len(t, observation.statusUpdates, 2)
				assert.Len(t, observation.statusUpdates[0].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[0].UsedByInstances, 1)
				assert.Len(t, observation.statusUpdates[0].Conditions, 1)
				condition := observation.statusUpdates[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActive, v1alpha2.ConditionReason(condition.Reason))

				assert.Len(t, observation.statusUpdates[1].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[1].UsedByInstances, 1)
				assert.Len(t, observation.statusUpdates[1].Conditions, 1)
				condition = observation.statusUpdates[1].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetUnloadingFailed, v1alpha2.ConditionReason(condition.Reason))
			},
		},
		{
			uc:   "a ruleset is added and then updated",
			conf: []byte("auth_class: bar"),
			writeResponse: func() ResponseWriter {
				callIdx := 0

				return func(t *testing.T, watchRequest bool, w http.ResponseWriter) {
					t.Helper()

					w.Header().Set("Content-Type", "application/json")
					if watchRequest {
						callIdx++

						evt := watch.Event{
							Type: watch.Added,
							Object: &v1alpha2.RuleSet{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									ResourceVersion:   "715382",
									Name:              "test-rule",
									Namespace:         "foo",
									UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
									Generation:        int64(callIdx),
									CreationTimestamp: metav1.NewTime(time.Now()),
								},
								Spec: v1alpha2.RuleSetSpec{
									AuthClassName: "bar",
									Rules: []config2.Rule{
										{
											ID: "test",
											RuleMatcher: config2.Matcher{
												URL:      "http://foo.bar",
												Strategy: "glob",
											},
											Backend: &config2.Backend{
												Host: "bar",
												URLRewriter: &config2.URLRewriter{
													Scheme:              "http",
													PathPrefixToCut:     "/foo",
													PathPrefixToAdd:     "/bar",
													QueryParamsToRemove: []string{"baz"},
												},
											},
											Methods: []string{http.MethodGet},
											Execute: []config.MechanismConfig{
												{"authenticator": "authn"},
												{"authorizer": "authz"},
											},
										},
									},
								},
							},
						}

						switch callIdx {
						case 1:
							// add a rule set
							var watchEvt metav1.WatchEvent

							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						case 2:
							// update it
							var watchEvt metav1.WatchEvent

							evt.Type = watch.Modified
							ruleSet := evt.Object.(*v1alpha2.RuleSet) // nolint:forcetypeassert
							ruleSet.ResourceVersion = "715384"
							ruleSet.Generation = int64(callIdx)
							ruleSet.Spec = v1alpha2.RuleSetSpec{
								AuthClassName: "bar",
								Rules: []config2.Rule{
									{
										ID: "test",
										RuleMatcher: config2.Matcher{
											URL:      "http://foo.bar",
											Strategy: "glob",
										},
										Backend: &config2.Backend{
											Host: "bar",
											URLRewriter: &config2.URLRewriter{
												Scheme:              "http",
												PathPrefixToCut:     "/foo",
												PathPrefixToAdd:     "/bar",
												QueryParamsToRemove: []string{"baz"},
											},
										},
										Methods: []string{http.MethodGet},
										Execute: []config.MechanismConfig{
											{"authenticator": "test_authn"},
											{"authorizer": "test_authz"},
										},
									},
								},
							}
							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						default:
							// no changes
							time.Sleep(1 * time.Second)
							w.WriteHeader(http.StatusInternalServerError)
						}
					} else {
						// empty rule set initially
						rls := v1alpha2.RuleSetList{
							TypeMeta: metav1.TypeMeta{
								APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
								Kind:       "RuleSetList",
							},
							ListMeta: metav1.ListMeta{
								ResourceVersion: "735820",
							},
						}

						rawRls, err := json.Marshal(rls)
						require.NoError(t, err)

						_, err = w.Write(rawRls)
						require.NoError(t, err)
					}
				}
			}(),
			writeStatus: func() StatusWriter {
				callIdx := 0

				rs := v1alpha2.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						ResourceVersion:   "715383",
						Name:              "test-rule",
						Namespace:         "foo",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha2.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								RuleMatcher: config2.Matcher{
									URL:      "http://foo.bar",
									Strategy: "glob",
								},
								Backend: &config2.Backend{
									Host: "bar",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Methods: []string{http.MethodGet},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}

				return func(t *testing.T, r *http.Request, w http.ResponseWriter) {
					t.Helper()

					callIdx++

					status := StatusUpdate{}
					err := json.NewDecoder(r.Body).Decode(&status)
					require.NoError(t, err)

					observations.statusUpdates = append(observations.statusUpdates, &status.Status)

					switch callIdx {
					case 1:
						rs.ResourceVersion = "715383"
						rs.Generation = int64(callIdx)
						rs.Status = status.Status
					case 2:
						rs.ResourceVersion = "715385"
						rs.Generation = int64(callIdx)
						rs.Status = status.Status
						rs.Spec.Rules[0].Execute = []config.MechanismConfig{
							{"authenticator": "test_authn"},
							{"authorizer": "test_authz"},
						}
					}

					data, err := json.Marshal(rs)
					require.NoError(t, err)

					w.Header().Set("Content-Type", "application/json")
					w.Write(data)
				}
			}(),
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()

				processor.EXPECT().OnUpdated(mock.Anything).
					Run(mock2.NewArgumentCaptor[*config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, observation *Observations, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				ruleSet := mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, ruleSet.Source, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86")
				assert.Equal(t, "1alpha2", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				createdRule := ruleSet.Rules[0]
				assert.Equal(t, "test", createdRule.ID)
				assert.Equal(t, "http://foo.bar", createdRule.RuleMatcher.URL)
				assert.Equal(t, "bar", createdRule.Backend.Host)
				assert.Equal(t, "glob", createdRule.RuleMatcher.Strategy)
				assert.Len(t, createdRule.Methods, 1)
				assert.Contains(t, createdRule.Methods, http.MethodGet)
				assert.Empty(t, createdRule.ErrorHandler)
				assert.Len(t, createdRule.Execute, 2)
				assert.Equal(t, "authn", createdRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", createdRule.Execute[1]["authorizer"])

				ruleSet = mock2.ArgumentCaptorFrom[*config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Equal(t, ruleSet.Source, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86")
				assert.Equal(t, "1alpha2", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				updatedRule := ruleSet.Rules[0]
				assert.Equal(t, "test", updatedRule.ID)
				assert.Equal(t, "http://foo.bar", updatedRule.RuleMatcher.URL)
				assert.Equal(t, "bar", updatedRule.Backend.Host)
				assert.Equal(t, "glob", updatedRule.RuleMatcher.Strategy)
				assert.Len(t, updatedRule.Methods, 1)
				assert.Contains(t, updatedRule.Methods, http.MethodGet)
				assert.Empty(t, updatedRule.ErrorHandler)
				assert.Len(t, updatedRule.Execute, 2)
				assert.Equal(t, "test_authn", updatedRule.Execute[0]["authenticator"])
				assert.Equal(t, "test_authz", updatedRule.Execute[1]["authorizer"])

				assert.Len(t, observation.statusUpdates, 2)
				assert.Len(t, observation.statusUpdates[0].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[0].UsedByInstances, 1)
				assert.Len(t, observation.statusUpdates[0].Conditions, 1)
				condition := observation.statusUpdates[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActive, v1alpha2.ConditionReason(condition.Reason))

				assert.Len(t, observation.statusUpdates[1].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[1].UsedByInstances, 1)
				assert.Len(t, observation.statusUpdates[1].Conditions, 1)
				condition = observation.statusUpdates[1].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActive, v1alpha2.ConditionReason(condition.Reason))
			},
		},
		{
			uc:   "failed updating rule set",
			conf: []byte("auth_class: bar"),
			writeResponse: func() ResponseWriter {
				callIdx := 0

				return func(t *testing.T, watchRequest bool, w http.ResponseWriter) {
					t.Helper()

					w.Header().Set("Content-Type", "application/json")
					if watchRequest {
						callIdx++

						evt := watch.Event{
							Type: watch.Added,
							Object: &v1alpha2.RuleSet{
								TypeMeta: metav1.TypeMeta{
									APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
									Kind:       "RuleSet",
								},
								ObjectMeta: metav1.ObjectMeta{
									ResourceVersion:   "715382",
									Name:              "test-rule",
									Namespace:         "foo",
									UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
									Generation:        int64(callIdx),
									CreationTimestamp: metav1.NewTime(time.Now()),
								},
								Spec: v1alpha2.RuleSetSpec{
									AuthClassName: "bar",
									Rules: []config2.Rule{
										{
											ID: "test",
											RuleMatcher: config2.Matcher{
												URL:      "http://foo.bar",
												Strategy: "glob",
											},
											Backend: &config2.Backend{
												Host: "bar",
												URLRewriter: &config2.URLRewriter{
													Scheme:              "http",
													PathPrefixToCut:     "/foo",
													PathPrefixToAdd:     "/bar",
													QueryParamsToRemove: []string{"baz"},
												},
											},
											Methods: []string{http.MethodGet},
											Execute: []config.MechanismConfig{
												{"authenticator": "authn"},
												{"authorizer": "authz"},
											},
										},
									},
								},
							},
						}

						switch callIdx {
						case 1:
							// add a rule set
							var watchEvt metav1.WatchEvent

							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						case 2:
							// update it
							var watchEvt metav1.WatchEvent

							evt.Type = watch.Modified
							ruleSet := evt.Object.(*v1alpha2.RuleSet) // nolint:forcetypeassert
							ruleSet.ResourceVersion = "715384"
							ruleSet.Generation = int64(callIdx)
							ruleSet.Spec = v1alpha2.RuleSetSpec{
								AuthClassName: "bar",
								Rules: []config2.Rule{
									{
										ID: "test",
										RuleMatcher: config2.Matcher{
											URL:      "http://foo.bar",
											Strategy: "glob",
										},
										Backend: &config2.Backend{
											Host: "baz",
											URLRewriter: &config2.URLRewriter{
												Scheme:              "http",
												PathPrefixToCut:     "/foo",
												PathPrefixToAdd:     "/bar",
												QueryParamsToRemove: []string{"baz"},
											},
										},
										Methods: []string{http.MethodGet},
										Execute: []config.MechanismConfig{
											{"authenticator": "test_authn"},
											{"authorizer": "test_authz"},
										},
									},
								},
							}
							err := metav1.Convert_watch_Event_To_v1_WatchEvent(&evt, &watchEvt, nil)
							require.NoError(t, err)

							rawEvt, err := json.Marshal(watchEvt)
							require.NoError(t, err)

							_, err = w.Write(rawEvt)
							require.NoError(t, err)
						default:
							// no changes
							time.Sleep(1 * time.Second)
							w.WriteHeader(http.StatusInternalServerError)
						}
					} else {
						// empty rule set initially
						rls := v1alpha2.RuleSetList{
							TypeMeta: metav1.TypeMeta{
								APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
								Kind:       "RuleSetList",
							},
							ListMeta: metav1.ListMeta{
								ResourceVersion: "735820",
							},
						}

						rawRls, err := json.Marshal(rls)
						require.NoError(t, err)

						_, err = w.Write(rawRls)
						require.NoError(t, err)
					}
				}
			}(),
			writeStatus: func() StatusWriter {
				callIdx := 0

				rs := v1alpha2.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: fmt.Sprintf("%s/%s", v1alpha2.GroupName, v1alpha2.GroupVersion),
						Kind:       "RuleSet",
					},
					ObjectMeta: metav1.ObjectMeta{
						ResourceVersion:   "715383",
						Name:              "test-rule",
						Namespace:         "foo",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1alpha2.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								RuleMatcher: config2.Matcher{
									URL:      "http://foo.bar",
									Strategy: "glob",
								},
								Backend: &config2.Backend{
									Host: "bar",
									URLRewriter: &config2.URLRewriter{
										Scheme:              "http",
										PathPrefixToCut:     "/foo",
										PathPrefixToAdd:     "/bar",
										QueryParamsToRemove: []string{"baz"},
									},
								},
								Methods: []string{http.MethodGet},
								Execute: []config.MechanismConfig{
									{"authenticator": "authn"},
									{"authorizer": "authz"},
								},
							},
						},
					},
				}

				return func(t *testing.T, r *http.Request, w http.ResponseWriter) {
					t.Helper()

					callIdx++

					status := StatusUpdate{}
					err := json.NewDecoder(r.Body).Decode(&status)
					require.NoError(t, err)

					observations.statusUpdates = append(observations.statusUpdates, &status.Status)

					switch callIdx {
					case 1:
						rs.ResourceVersion = "715383"
						rs.Generation = int64(callIdx)
						rs.Status = status.Status
					case 2:
						rs.ResourceVersion = "715385"
						rs.Generation = int64(callIdx)
						rs.Status = status.Status
						rs.Spec.Rules[0].Execute = []config.MechanismConfig{
							{"authenticator": "test_authn"},
							{"authorizer": "test_authz"},
						}
					}

					data, err := json.Marshal(rs)
					require.NoError(t, err)

					w.Header().Set("Content-Type", "application/json")
					w.Write(data)
				}
			}(),
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything).Return(nil).Once()
				processor.EXPECT().OnUpdated(mock.Anything).Return(testsupport.ErrTestPurpose).Once()
			},
			assert: func(t *testing.T, observation *Observations, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				assert.Len(t, observation.statusUpdates, 2)
				assert.Len(t, observation.statusUpdates[0].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[0].UsedByInstances, 1)
				assert.Len(t, observation.statusUpdates[0].Conditions, 1)
				condition := observation.statusUpdates[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActive, v1alpha2.ConditionReason(condition.Reason))

				assert.Len(t, observation.statusUpdates[1].MatchingInstances, 1)
				assert.Len(t, observation.statusUpdates[1].UsedByInstances, 0)
				assert.Len(t, observation.statusUpdates[1].Conditions, 1)
				condition = observation.statusUpdates[1].Conditions[0]
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Equal(t, v1alpha2.ConditionRuleSetActivationFailed, v1alpha2.ConditionReason(condition.Reason))
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			observations.statusUpdates = nil
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			conf := &config.Configuration{
				Rules: config.Rules{
					Providers: config.RuleProviders{Kubernetes: providerConf},
				},
			}
			k8sCF := func() (*rest.Config, error) { return &rest.Config{Host: srv.URL}, nil }

			setupProcessor := x.IfThenElse(tc.setupProcessor != nil,
				tc.setupProcessor,
				func(t *testing.T, _ *mocks.RuleSetProcessorMock) { t.Helper() })

			processor := mocks.NewRuleSetProcessorMock(t)
			setupProcessor(t, processor)

			logs := &strings.Builder{}
			prov, err := newProvider(zerolog.New(logs), conf, k8sCF, processor, mocks.NewFactoryMock(t))
			require.NoError(t, err)

			ctx := context.Background()
			writeResponse = tc.writeResponse
			writeStatus = tc.writeStatus

			// WHEN
			err = prov.Start(ctx)

			defer prov.Stop(ctx) //nolint:errcheck

			// THEN
			require.NoError(t, err)
			tc.assert(t, observations, processor)
		})
	}
}
