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
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha4"
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
	for uc, tc := range map[string]struct {
		conf   []byte
		assert func(t *testing.T, err error, prov *Provider)
	}{
		"with unknown field": {
			conf: []byte(`foo: bar`),
			assert: func(t *testing.T, err error, _ *Provider) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to decode")
			},
		},
		"with empty configuration": {
			conf: []byte(`{}`),
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, DefaultClass, prov.ac)
				assert.Nil(t, prov.cancel)
				assert.NotNil(t, prov.cl)
			},
		},
		"with auth_class configured": {
			conf: []byte(`auth_class: foo`),
			assert: func(t *testing.T, err error, prov *Provider) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, prov)
				assert.Equal(t, "foo", prov.ac)
				assert.Nil(t, prov.cancel)
				assert.NotNil(t, prov.cl)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			conf := &config.Configuration{
				Providers: config.RuleProviders{Kubernetes: providerConf},
			}
			k8sCF := func() (*rest.Config, error) { return &rest.Config{Host: "http://localhost:80001"}, nil }

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Config().Return(conf)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			prov, err := NewProvider(appCtx, k8sCF, mocks.NewRuleSetProcessorMock(t), mocks.NewFactoryMock(t))

			// THEN
			tc.assert(t, err, prov)
		})
	}
}

type RuleSetResourceHandler struct {
	statusUpdates       []*v1alpha4.RuleSetStatus
	listCallIdx         int
	watchCallIdx        int
	updateStatusCallIdx int

	rsCurrent v1alpha4.RuleSet

	rsUpdatedEvt chan v1alpha4.RuleSet
	rsCurrentEvt chan v1alpha4.RuleSet

	updateStatus func(rs v1alpha4.RuleSet, callIdx int) (*metav1.Status, error)
	watchEvent   func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error)
}

func (h *RuleSetResourceHandler) close() {
	close(h.rsUpdatedEvt)
	close(h.rsCurrentEvt)
}

func (h *RuleSetResourceHandler) handle(t *testing.T, r *http.Request, w http.ResponseWriter) {
	t.Helper()

	switch {
	case strings.HasSuffix(r.URL.Path, "/status"):
		h.updateStatusCallIdx++
		h.writeUpdateStatusResponse(t, r, w)
	case r.URL.Query().Get("watch") == "true":
		h.watchCallIdx++
		h.writeWatchResponse(t, w)
	case r.URL.Path == "/apis/heimdall.dadrus.github.com/v1alpha4/rulesets":
		h.listCallIdx++
		h.writeListResponse(t, w)
	default:
		// GET
		h.writeSingleRuleResponse(t, w)
	}
}

func (h *RuleSetResourceHandler) writeWatchResponse(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	got, ok := <-h.rsUpdatedEvt
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	wEvt, err := h.watchEvent(got, h.watchCallIdx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	h.rsCurrent = *wEvt.Object.(*v1alpha4.RuleSet) // nolint: forcetypeassert

	h.rsCurrentEvt <- h.rsCurrent

	var evt metav1.WatchEvent

	err = metav1.Convert_watch_Event_To_v1_WatchEvent(&wEvt, &evt, nil)
	require.NoError(t, err)

	rawEvt, err := json.Marshal(evt)
	require.NoError(t, err)

	w.Header().Set("Content-Type", "application/json")

	_, err = w.Write(rawEvt)
	require.NoError(t, err)
}

func (h *RuleSetResourceHandler) writeListResponse(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	rs := v1alpha4.RuleSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: fmt.Sprintf("%s/%s", v1alpha4.GroupName, v1alpha4.GroupVersion),
			Kind:       "RuleSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-rule",
			Namespace:         "foo",
			ResourceVersion:   "100",
			UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
			Generation:        1,
			CreationTimestamp: metav1.NewTime(time.Now()),
		},
		Spec: v1alpha4.RuleSetSpec{
			AuthClassName: "bar",
			Rules: []config2.Rule{
				{
					ID: "test",
					Matcher: config2.Matcher{
						Routes:  []config2.Route{{Path: "/"}},
						Scheme:  "http",
						Methods: []string{http.MethodGet},
						Hosts:   []config2.HostMatcher{{Value: "foo.bar", Type: "glob"}},
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
					Execute: []config.MechanismConfig{
						{"authenticator": "authn"},
						{"authorizer": "authz"},
					},
				},
			},
		},
	}

	rsl := v1alpha4.RuleSetList{
		TypeMeta: metav1.TypeMeta{
			APIVersion: fmt.Sprintf("%s/%s", v1alpha4.GroupName, v1alpha4.GroupVersion),
			Kind:       "RuleSetList",
		},
		ListMeta: metav1.ListMeta{ResourceVersion: "735820"},
		Items:    []v1alpha4.RuleSet{rs},
	}

	h.rsUpdatedEvt <- rs

	rawRls, err := json.Marshal(rsl)
	require.NoError(t, err)

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(rawRls)
	require.NoError(t, err)
}

func (h *RuleSetResourceHandler) writeUpdateStatusResponse(t *testing.T, r *http.Request, w http.ResponseWriter) {
	t.Helper()

	got, ok := <-h.rsCurrentEvt
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
	}

	rawRS, err := json.Marshal(got)
	require.NoError(t, err)

	data, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	patch, err := jsonpatch.DecodePatch(data)
	require.NoError(t, err)

	updatedRS, err := patch.Apply(rawRS)
	require.NoError(t, err)

	var newRS v1alpha4.RuleSet
	err = json.Unmarshal(updatedRS, &newRS)

	require.NoError(t, err)

	rv, err := strconv.Atoi(newRS.ResourceVersion)
	require.NoError(t, err)

	newRS.ResourceVersion = strconv.Itoa(rv + 1)

	h.rsUpdatedEvt <- newRS

	if h.updateStatus != nil {
		status, err := h.updateStatus(newRS, h.updateStatusCallIdx)
		if status != nil {
			data, err := json.Marshal(status)
			require.NoError(t, err)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(int(status.Code))
			_, err = w.Write(data)
			require.NoError(t, err)

			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(err.Error()))
			require.NoError(t, err)

			return
		}
	}

	h.statusUpdates = append(h.statusUpdates, &newRS.Status)

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(updatedRS)
	require.NoError(t, err)
}

func (h *RuleSetResourceHandler) writeSingleRuleResponse(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	rawRS, err := json.Marshal(h.rsCurrent)
	require.NoError(t, err)

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(rawRS)
	require.NoError(t, err)

	h.rsCurrentEvt <- h.rsCurrent
}

func TestProviderLifecycle(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		conf           []byte
		watchEvent     func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error)
		updateStatus   func(rs v1alpha4.RuleSet, callIdx int) (*metav1.Status, error)
		setupProcessor func(t *testing.T, processor *mocks.RuleSetProcessorMock)
		assert         func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, processor *mocks.RuleSetProcessorMock)
	}{
		"rule set added": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				default:
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				_, ruleSet := mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Contains(t, ruleSet.Source, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86")
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				rule := ruleSet.Rules[0]
				assert.Equal(t, "test", rule.ID)
				assert.Equal(t, "http", rule.Matcher.Scheme)
				assert.Len(t, rule.Matcher.Hosts, 1)
				assert.Equal(t, "foo.bar", rule.Matcher.Hosts[0].Value)
				assert.Equal(t, "glob", rule.Matcher.Hosts[0].Type)
				assert.Len(t, rule.Matcher.Routes, 1)
				assert.Equal(t, "/", rule.Matcher.Routes[0].Path)
				assert.Len(t, rule.Matcher.Methods, 1)
				assert.Contains(t, rule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "baz", rule.Backend.Host)
				assert.Empty(t, rule.ErrorHandler)
				assert.Len(t, rule.Execute, 2)
				assert.Equal(t, "authn", rule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", rule.Execute[1]["authorizer"])

				assert.Len(t, *statusList, 1)
				assert.Equal(t, "1/1", (*statusList)[0].ActiveIn)

				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))
			},
		},
		"adding rule set fails": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, _ int) (watch.Event, error) {
				return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).Return(errors.New("test error")).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, _ *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				assert.Len(t, *statusList, 1)
				assert.Equal(t, "0/1", (*statusList)[0].ActiveIn)

				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActivationFailed, v1alpha4.ConditionReason(condition.Reason))
			},
		},
		"a ruleset is added and then removed": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				case 2:
					return watch.Event{Type: watch.Deleted, Object: &rs}, nil
				default:
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			updateStatus: func(rs v1alpha4.RuleSet, callIdx int) (*metav1.Status, error) {
				switch callIdx {
				case 2:
					return &metav1.Status{
						Status:  "Failure",
						Message: "RuleSet gone",
						Reason:  metav1.StatusReasonNotFound,
						Details: &metav1.StatusDetails{
							Name:  rs.Name,
							Group: "heimdall.dadrus.github.com",
							Kind:  "rulesets",
						},
						Code: http.StatusNotFound,
					}, nil
				default:
					return nil, nil //nolint:nilnil
				}
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()

				processor.EXPECT().OnDeleted(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				_, ruleSet := mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				createdRule := ruleSet.Rules[0]
				assert.Equal(t, "test", createdRule.ID)
				assert.Equal(t, "http", createdRule.Matcher.Scheme)
				assert.Len(t, createdRule.Matcher.Hosts, 1)
				assert.Equal(t, "glob", createdRule.Matcher.Hosts[0].Type)
				assert.Equal(t, "foo.bar", createdRule.Matcher.Hosts[0].Value)
				assert.Len(t, createdRule.Matcher.Routes, 1)
				assert.Equal(t, "/", createdRule.Matcher.Routes[0].Path)
				assert.Len(t, createdRule.Matcher.Methods, 1)
				assert.Contains(t, createdRule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "baz", createdRule.Backend.Host)
				assert.Empty(t, createdRule.ErrorHandler)
				assert.Len(t, createdRule.Execute, 2)
				assert.Equal(t, "authn", createdRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", createdRule.Execute[1]["authorizer"])

				_, ruleSet = mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)

				assert.Len(t, *statusList, 1)

				assert.Equal(t, "1/1", (*statusList)[0].ActiveIn)
				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))
			},
		},
		"a ruleset is added with failing status update": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					rv, err := strconv.Atoi(rs.ResourceVersion)
					require.NoError(t, err)

					rs.ResourceVersion = strconv.Itoa(rv + 1)

					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				default:
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			updateStatus: func(_ v1alpha4.RuleSet, _ int) (*metav1.Status, error) {
				return nil, errors.New("test error")
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				_, ruleSet := mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				createdRule := ruleSet.Rules[0]
				assert.Equal(t, "test", createdRule.ID)
				assert.Equal(t, "http", createdRule.Matcher.Scheme)
				assert.Len(t, createdRule.Matcher.Hosts, 1)
				assert.Equal(t, "glob", createdRule.Matcher.Hosts[0].Type)
				assert.Equal(t, "foo.bar", createdRule.Matcher.Hosts[0].Value)
				assert.Len(t, createdRule.Matcher.Routes, 1)
				assert.Equal(t, "/", createdRule.Matcher.Routes[0].Path)
				assert.Len(t, createdRule.Matcher.Methods, 1)
				assert.Contains(t, createdRule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "baz", createdRule.Backend.Host)
				assert.Empty(t, createdRule.ErrorHandler)
				assert.Len(t, createdRule.Execute, 2)
				assert.Equal(t, "authn", createdRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", createdRule.Execute[1]["authorizer"])

				assert.Empty(t, *statusList)
			},
		},
		"a ruleset is added with status resulting in a conflict": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					rv, err := strconv.Atoi(rs.ResourceVersion)
					require.NoError(t, err)

					rs.ResourceVersion = strconv.Itoa(rv + 1)

					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				default:
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			updateStatus: func(rs v1alpha4.RuleSet, callIdx int) (*metav1.Status, error) {
				switch callIdx {
				case 1:
					return &metav1.Status{
						Status:  "Failure",
						Message: "RuleSet conflict",
						Reason:  metav1.StatusReasonConflict,
						Details: &metav1.StatusDetails{
							Name:  rs.Name,
							Group: "heimdall.dadrus.github.com",
							Kind:  "rulesets",
						},
						Code: http.StatusConflict,
					}, nil
				default:
					return nil, nil //nolint:nilnil
				}
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				_, ruleSet := mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				createdRule := ruleSet.Rules[0]
				assert.Equal(t, "test", createdRule.ID)
				assert.Equal(t, "http", createdRule.Matcher.Scheme)
				assert.Len(t, createdRule.Matcher.Hosts, 1)
				assert.Equal(t, "glob", createdRule.Matcher.Hosts[0].Type)
				assert.Equal(t, "foo.bar", createdRule.Matcher.Hosts[0].Value)
				assert.Len(t, createdRule.Matcher.Routes, 1)
				assert.Equal(t, "/", createdRule.Matcher.Routes[0].Path)
				assert.Len(t, createdRule.Matcher.Methods, 1)
				assert.Contains(t, createdRule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "baz", createdRule.Backend.Host)
				assert.Empty(t, createdRule.ErrorHandler)
				assert.Len(t, createdRule.Execute, 2)
				assert.Equal(t, "authn", createdRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", createdRule.Execute[1]["authorizer"])

				assert.Len(t, *statusList, 1)

				assert.Equal(t, "1/1", (*statusList)[0].ActiveIn)
				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))
			},
		},
		"removing rule set fails": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				case 2:
					return watch.Event{Type: watch.Deleted, Object: &rs}, nil
				default:
					// no changes
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).Return(nil).Once()
				processor.EXPECT().OnDeleted(mock.Anything, mock.Anything).Return(errors.New("test error")).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, _ *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				assert.Len(t, *statusList, 2)
				assert.Equal(t, "1/1", (*statusList)[0].ActiveIn)
				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))

				assert.Equal(t, "1/1", (*statusList)[1].ActiveIn)
				assert.Len(t, (*statusList)[1].Conditions, 1)
				condition = (*statusList)[1].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetUnloadingFailed, v1alpha4.ConditionReason(condition.Reason))
			},
		},
		"a ruleset is added and then updated": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				case 2:
					rv, err := strconv.Atoi(rs.ResourceVersion)
					require.NoError(t, err)

					rs.ResourceVersion = strconv.Itoa(rv + 1)
					rs.Generation++
					rs.Spec = v1alpha4.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								Matcher: config2.Matcher{
									Routes:  []config2.Route{{Path: "/"}},
									Scheme:  "http",
									Methods: []string{http.MethodGet},
									Hosts:   []config2.HostMatcher{{Value: "foo.bar", Type: "glob"}},
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
								Execute: []config.MechanismConfig{
									{"authenticator": "test_authn"},
									{"authorizer": "test_authz"},
								},
							},
						},
					}

					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				default:
					// no changes
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()

				processor.EXPECT().OnUpdated(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				_, ruleSet := mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				createdRule := ruleSet.Rules[0]
				assert.Equal(t, "test", createdRule.ID)
				assert.Equal(t, "http", createdRule.Matcher.Scheme)
				assert.Len(t, createdRule.Matcher.Hosts, 1)
				assert.Equal(t, "glob", createdRule.Matcher.Hosts[0].Type)
				assert.Equal(t, "foo.bar", createdRule.Matcher.Hosts[0].Value)
				assert.Len(t, createdRule.Matcher.Routes, 1)
				assert.Equal(t, "/", createdRule.Matcher.Routes[0].Path)
				assert.Len(t, createdRule.Matcher.Methods, 1)
				assert.Contains(t, createdRule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "baz", createdRule.Backend.Host)
				assert.Empty(t, createdRule.ErrorHandler)
				assert.Len(t, createdRule.Execute, 2)
				assert.Equal(t, "authn", createdRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", createdRule.Execute[1]["authorizer"])

				_, ruleSet = mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				updatedRule := ruleSet.Rules[0]
				assert.Equal(t, "test", updatedRule.ID)
				assert.Equal(t, "http", createdRule.Matcher.Scheme)
				assert.Len(t, createdRule.Matcher.Hosts, 1)
				assert.Equal(t, "glob", createdRule.Matcher.Hosts[0].Type)
				assert.Equal(t, "foo.bar", createdRule.Matcher.Hosts[0].Value)
				assert.Len(t, createdRule.Matcher.Routes, 1)
				assert.Equal(t, "/", createdRule.Matcher.Routes[0].Path)
				assert.Len(t, createdRule.Matcher.Methods, 1)
				assert.Contains(t, createdRule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "bar", updatedRule.Backend.Host)
				assert.Empty(t, updatedRule.ErrorHandler)
				assert.Len(t, updatedRule.Execute, 2)
				assert.Equal(t, "test_authn", updatedRule.Execute[0]["authenticator"])
				assert.Equal(t, "test_authz", updatedRule.Execute[1]["authorizer"])

				assert.Len(t, *statusList, 2)
				assert.Equal(t, "1/1", (*statusList)[0].ActiveIn)
				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))

				assert.Equal(t, "1/1", (*statusList)[1].ActiveIn)
				assert.Len(t, (*statusList)[1].Conditions, 1)
				condition = (*statusList)[1].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))
			},
		},
		"a ruleset is added and then updated with a mismatching authClassName": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					rs.Status.ActiveIn = "1/1"

					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				case 2:
					rv, err := strconv.Atoi(rs.ResourceVersion)
					require.NoError(t, err)

					rs.ResourceVersion = strconv.Itoa(rv + 1)
					rs.Generation++
					rs.Spec.AuthClassName = "foo"

					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				default:
					// no changes
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Capture).
					Return(nil).Once()

				processor.EXPECT().OnDeleted(mock.Anything, mock.Anything).
					Run(mock2.NewArgumentCaptor2[context.Context, *config2.RuleSet](&processor.Mock, "captor2").Capture).
					Return(nil).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				_, ruleSet := mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor1").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				createdRule := ruleSet.Rules[0]
				assert.Equal(t, "test", createdRule.ID)
				assert.Equal(t, "http", createdRule.Matcher.Scheme)
				assert.Len(t, createdRule.Matcher.Hosts, 1)
				assert.Equal(t, "glob", createdRule.Matcher.Hosts[0].Type)
				assert.Equal(t, "foo.bar", createdRule.Matcher.Hosts[0].Value)
				assert.Len(t, createdRule.Matcher.Routes, 1)
				assert.Equal(t, "/", createdRule.Matcher.Routes[0].Path)
				assert.Len(t, createdRule.Matcher.Methods, 1)
				assert.Contains(t, createdRule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "baz", createdRule.Backend.Host)
				assert.Empty(t, createdRule.ErrorHandler)
				assert.Len(t, createdRule.Execute, 2)
				assert.Equal(t, "authn", createdRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", createdRule.Execute[1]["authorizer"])

				_, ruleSet = mock2.ArgumentCaptor2From[context.Context, *config2.RuleSet](&processor.Mock, "captor2").Value()
				assert.Equal(t, "kubernetes:foo:dfb2a2f1-1ad2-4d8c-8456-516fc94abb86", ruleSet.Source)
				assert.Equal(t, "1alpha4", ruleSet.Version)
				assert.Equal(t, "test-rule", ruleSet.Name)
				assert.Len(t, ruleSet.Rules, 1)

				deleteRule := ruleSet.Rules[0]
				assert.Equal(t, "test", deleteRule.ID)
				assert.Equal(t, "http", createdRule.Matcher.Scheme)
				assert.Len(t, createdRule.Matcher.Hosts, 1)
				assert.Equal(t, "glob", createdRule.Matcher.Hosts[0].Type)
				assert.Equal(t, "foo.bar", createdRule.Matcher.Hosts[0].Value)
				assert.Len(t, createdRule.Matcher.Routes, 1)
				assert.Equal(t, "/", createdRule.Matcher.Routes[0].Path)
				assert.Len(t, createdRule.Matcher.Methods, 1)
				assert.Contains(t, createdRule.Matcher.Methods, http.MethodGet)
				assert.Equal(t, "baz", deleteRule.Backend.Host)
				assert.Empty(t, deleteRule.ErrorHandler)
				assert.Len(t, deleteRule.Execute, 2)
				assert.Equal(t, "authn", deleteRule.Execute[0]["authenticator"])
				assert.Equal(t, "authz", deleteRule.Execute[1]["authorizer"])

				assert.NotEmpty(t, *statusList)
				assert.Equal(t, "1/1", (*statusList)[0].ActiveIn)
				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))
			},
		},
		"failed updating rule set": {
			conf: []byte("auth_class: bar"),
			watchEvent: func(rs v1alpha4.RuleSet, callIdx int) (watch.Event, error) {
				switch callIdx {
				case 1:
					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				case 2:
					rv, err := strconv.Atoi(rs.ResourceVersion)
					require.NoError(t, err)

					rs.ResourceVersion = strconv.Itoa(rv + 1)
					rs.Generation++
					rs.Spec = v1alpha4.RuleSetSpec{
						AuthClassName: "bar",
						Rules: []config2.Rule{
							{
								ID: "test",
								Matcher: config2.Matcher{
									Routes:  []config2.Route{{Path: "/"}},
									Scheme:  "http",
									Methods: []string{http.MethodGet},
									Hosts:   []config2.HostMatcher{{Value: "foo.bar", Type: "glob"}},
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
								Execute: []config.MechanismConfig{
									{"authenticator": "test_authn"},
									{"authorizer": "test_authz"},
								},
							},
						},
					}

					return watch.Event{Type: watch.Modified, Object: &rs}, nil
				default:
					// no changes
					return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
				}
			},
			setupProcessor: func(t *testing.T, processor *mocks.RuleSetProcessorMock) {
				t.Helper()

				processor.EXPECT().OnCreated(mock.Anything, mock.Anything).Return(nil).Once()
				processor.EXPECT().OnUpdated(mock.Anything, mock.Anything).Return(errors.New("test error")).Once()
			},
			assert: func(t *testing.T, statusList *[]*v1alpha4.RuleSetStatus, _ *mocks.RuleSetProcessorMock) {
				t.Helper()

				time.Sleep(250 * time.Millisecond)

				assert.Len(t, *statusList, 2)
				assert.Equal(t, "1/1", (*statusList)[0].ActiveIn)
				assert.Len(t, (*statusList)[0].Conditions, 1)
				condition := (*statusList)[0].Conditions[0]
				assert.Equal(t, metav1.ConditionTrue, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActive, v1alpha4.ConditionReason(condition.Reason))

				assert.Equal(t, "0/1", (*statusList)[1].ActiveIn)
				assert.Len(t, (*statusList)[1].Conditions, 1)
				condition = (*statusList)[1].Conditions[0]
				assert.Equal(t, metav1.ConditionFalse, condition.Status)
				assert.Equal(t, v1alpha4.ConditionRuleSetActivationFailed, v1alpha4.ConditionReason(condition.Reason))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			providerConf, err := testsupport.DecodeTestConfig(tc.conf)
			require.NoError(t, err)

			handler := &RuleSetResourceHandler{
				rsUpdatedEvt: make(chan v1alpha4.RuleSet, 2),
				rsCurrentEvt: make(chan v1alpha4.RuleSet, 2),
				watchEvent:   tc.watchEvent,
				updateStatus: tc.updateStatus,
			}

			conf := &config.Configuration{
				Providers: config.RuleProviders{Kubernetes: providerConf},
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.handle(t, r, w)
			}))

			defer srv.Close()

			k8sCF := func() (*rest.Config, error) { return &rest.Config{Host: srv.URL}, nil }

			setupProcessor := x.IfThenElse(tc.setupProcessor != nil,
				tc.setupProcessor,
				func(t *testing.T, _ *mocks.RuleSetProcessorMock) { t.Helper() })

			processor := mocks.NewRuleSetProcessorMock(t)
			setupProcessor(t, processor)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Config().Return(conf)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prov, err := NewProvider(appCtx, k8sCF, processor, mocks.NewFactoryMock(t))
			require.NoError(t, err)

			ctx := t.Context()

			// WHEN
			err = prov.Start(ctx)

			defer func() {
				_ = prov.Stop(ctx) //nolint:errcheck

				handler.close()
			}()

			// THEN
			require.NoError(t, err)
			tc.assert(t, &handler.statusUpdates, processor)
		})
	}
}

func TestReconciliationLoopKeepsRunningAfterContextTimeout(t *testing.T) {
	t.Parallel()

	// GIVEN
	tb := &testsupport.TestingLog{TB: t}
	logger := zerolog.New(zerolog.TestWriter{T: tb})

	handler := &RuleSetResourceHandler{
		rsUpdatedEvt: make(chan v1alpha4.RuleSet, 2),
		rsCurrentEvt: make(chan v1alpha4.RuleSet, 2),
		watchEvent: func(rs v1alpha4.RuleSet, _ int) (watch.Event, error) {
			return watch.Event{Type: watch.Bookmark, Object: &rs}, nil
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.handle(t, r, w)
	}))

	defer srv.Close()

	conf := &config.Configuration{Providers: config.RuleProviders{Kubernetes: map[string]any{}}}
	k8sCF := func() (*rest.Config, error) { return &rest.Config{Host: srv.URL}, nil }
	processor := mocks.NewRuleSetProcessorMock(t)

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Config().Return(conf)
	appCtx.EXPECT().Logger().Return(logger)

	prov, err := NewProvider(appCtx, k8sCF, processor, mocks.NewFactoryMock(t))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()

	// WHEN
	err = prov.Start(ctx)

	defer func() {
		_ = prov.Stop(ctx) //nolint:errcheck

		handler.close()
	}()

	// THEN
	time.Sleep(200 * time.Millisecond)

	assert.NotContains(t, tb.CollectedLog(), "Reconciliation loop exited")

	require.NoError(t, err)
}
