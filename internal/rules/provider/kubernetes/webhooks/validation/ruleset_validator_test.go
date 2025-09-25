// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package validation

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	cfgv1beta1 "github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
)

func TestRulesetValidatorHandle(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		req            *request
		configureMocks func(t *testing.T, fm *mocks.FactoryMock)
		assert         func(t *testing.T, resp *response)
	}{
		"unsupported resource kind": {
			req: &request{
				Kind: metav1.GroupVersionKind{},
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.False(t, resp.Allowed)
				require.NotNil(t, resp.Result)
				assert.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
				assert.Equal(t, metav1.StatusFailure, resp.Result.Status)
				assert.Equal(t, "failed to unmarshal RuleSet", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Equal(t, ErrInvalidObject.Error(), resp.Result.Details.Causes[0].Message)
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Object", resp.Result.Details.Causes[0].Field)

			},
		},
		"unmarshalling error": {
			req: &request{
				Kind: metav1.GroupVersionKind{
					Kind:    v1beta1.ResourceName,
					Version: v1beta1.GroupVersion.Version,
					Group:   v1beta1.GroupVersion.Group,
				},
				Object: runtime.RawExtension{Raw: []byte("foo")},
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.False(t, resp.Allowed)
				require.NotNil(t, resp.Result)
				assert.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
				assert.Equal(t, metav1.StatusFailure, resp.Result.Status)
				assert.Equal(t, "failed to unmarshal RuleSet", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Contains(t, resp.Result.Details.Causes[0].Message, "looking for beginning of value")
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Object", resp.Result.Details.Causes[0].Field)
			},
		},
		"unsupported AuthClassName": {
			req: func() *request {
				ruleSet := v1beta1.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: v1beta1.GroupVersion.String(),
						Kind:       v1beta1.ResourceName,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702666",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1beta1.RuleSetSpec{AuthClassName: "foo"},
				}

				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				return &request{
					UID:       "ce409862-eae0-4704-b7d5-46634efdaf9b",
					Namespace: "test",
					Name:      "test-rules",
					Operation: admissionv1.Create,
					Kind: metav1.GroupVersionKind{
						Group:   v1beta1.GroupVersion.Group,
						Version: v1beta1.GroupVersion.Version,
						Kind:    v1beta1.ResourceName,
					},
					Resource: metav1.GroupVersionResource{
						Group:    v1beta1.GroupVersion.Group,
						Version:  v1beta1.GroupVersion.Version,
						Resource: v1beta1.ResourceListName,
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   v1beta1.GroupVersion.Group,
						Version: v1beta1.GroupVersion.Version,
						Kind:    v1beta1.ResourceName,
					},
					RequestResource: &metav1.GroupVersionResource{
						Group:    v1beta1.GroupVersion.Group,
						Version:  v1beta1.GroupVersion.Version,
						Resource: v1beta1.ResourceListName,
					},
					Object: runtime.RawExtension{Raw: data},
				}
			}(),
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.True(t, resp.Allowed)
				require.NotNil(t, resp.Result)
				assert.Equal(t, http.StatusOK, int(resp.Result.Code))
				assert.Equal(t, metav1.StatusSuccess, resp.Result.Status)
				assert.Contains(t, resp.Result.Message, "RuleSet ignored")
			},
		},
		"ruleset with two rules and both failing": {
			req: func() *request {
				ruleSet := v1beta1.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: v1beta1.GroupVersion.String(),
						Kind:       v1beta1.ResourceName,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702666",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1beta1.RuleSetSpec{
						Rules: []cfgv1beta1.Rule{
							{ID: "rule1"},
							{ID: "rule2"},
						},
					},
				}

				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				return &request{
					UID:       "ce409862-eae0-4704-b7d5-46634efdaf9b",
					Namespace: "test",
					Name:      "test-rules",
					Operation: admissionv1.Create,
					Kind: metav1.GroupVersionKind{
						Group:   v1beta1.GroupVersion.Group,
						Version: v1beta1.GroupVersion.Version,
						Kind:    v1beta1.ResourceName,
					},
					Resource: metav1.GroupVersionResource{
						Group:    v1beta1.GroupVersion.Group,
						Version:  v1beta1.GroupVersion.Version,
						Resource: v1beta1.ResourceListName,
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   v1beta1.GroupVersion.Group,
						Version: v1beta1.GroupVersion.Version,
						Kind:    v1beta1.ResourceName,
					},
					RequestResource: &metav1.GroupVersionResource{
						Group:    v1beta1.GroupVersion.Group,
						Version:  v1beta1.GroupVersion.Version,
						Resource: v1beta1.ResourceListName,
					},
					Object: runtime.RawExtension{Raw: data},
				}
			}(),
			configureMocks: func(t *testing.T, fm *mocks.FactoryMock) {
				t.Helper()

				fm.EXPECT().CreateRule(mock.Anything, mock.Anything, mock.Anything).
					Times(2).Return(nil, errors.New("test error"))
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.False(t, resp.Allowed)
				require.NotNil(t, resp.Result)
				assert.Equal(t, http.StatusForbidden, int(resp.Result.Code))
				assert.Equal(t, metav1.StatusFailure, resp.Result.Status)
				assert.Equal(t, "RuleSet invalid", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonForbidden, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 2)
				assert.Contains(t, resp.Result.Details.Causes[0].Message, "test error")
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Object.Spec.Rules[0]", resp.Result.Details.Causes[0].Field)
				assert.Contains(t, resp.Result.Details.Causes[1].Message, "test error")
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[1].Type)
				assert.Equal(t, "Object.Spec.Rules[1]", resp.Result.Details.Causes[1].Field)
			},
		},
		"successful validation": {
			req: func() *request {
				ruleSet := v1beta1.RuleSet{
					TypeMeta: metav1.TypeMeta{
						APIVersion: v1beta1.GroupVersion.String(),
						Kind:       v1beta1.ResourceName,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-rule",
						Namespace:         "foo",
						ResourceVersion:   "702666",
						UID:               "dfb2a2f1-1ad2-4d8c-8456-516fc94abb86",
						Generation:        1,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1beta1.RuleSetSpec{
						Rules: []cfgv1beta1.Rule{
							{ID: "rule1"},
						},
					},
				}

				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				return &request{
					UID:       "ce409862-eae0-4704-b7d5-46634efdaf9b",
					Namespace: "test",
					Name:      "test-rules",
					Operation: admissionv1.Create,
					Kind: metav1.GroupVersionKind{
						Group:   v1beta1.GroupVersion.Group,
						Version: v1beta1.GroupVersion.Version,
						Kind:    v1beta1.ResourceName,
					},
					Resource: metav1.GroupVersionResource{
						Group:    v1beta1.GroupVersion.Group,
						Version:  v1beta1.GroupVersion.Version,
						Resource: v1beta1.ResourceListName,
					},
					RequestKind: &metav1.GroupVersionKind{
						Group:   v1beta1.GroupVersion.Group,
						Version: v1beta1.GroupVersion.Version,
						Kind:    v1beta1.ResourceName,
					},
					RequestResource: &metav1.GroupVersionResource{
						Group:    v1beta1.GroupVersion.Group,
						Version:  v1beta1.GroupVersion.Version,
						Resource: v1beta1.ResourceListName,
					},
					Object: runtime.RawExtension{Raw: data},
				}
			}(),
			configureMocks: func(t *testing.T, fm *mocks.FactoryMock) {
				t.Helper()

				fm.EXPECT().CreateRule(mock.Anything, mock.Anything, mock.Anything).
					Once().Return(nil, nil)
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.True(t, resp.Allowed)
				require.NotNil(t, resp.Result)
				assert.Equal(t, http.StatusOK, int(resp.Result.Code))
				assert.Equal(t, metav1.StatusSuccess, resp.Result.Status)
				assert.Equal(t, "RuleSet valid", resp.Result.Message)
				require.Nil(t, resp.Result.Details)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			fm := mocks.NewFactoryMock(t)
			rsv := &rulesetValidator{f: fm}

			configureMocks := x.IfThenElse(
				tc.configureMocks != nil,
				tc.configureMocks,
				func(t *testing.T, _ *mocks.FactoryMock) { t.Helper() },
			)

			configureMocks(t, fm)

			resp := rsv.Handle(t.Context(), tc.req)

			tc.assert(t, resp)
		})
	}
}
