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

package conversion

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/api/common"
	cfgv1alpha4 "github.com/dadrus/heimdall/internal/rules/api/v1alpha4"
	cfgv1beta1 "github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha4"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
)

func TestRulSetConverterHandle(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		req    request
		assert func(t *testing.T, resp *response)
	}{
		"no objects for conversion provided": {
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "no objects to convert provided", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Equal(t, "no objects to convert provided", resp.Result.Details.Causes[0].Message)
				assert.Equal(t, metav1.CauseTypeFieldValueRequired, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects", resp.Result.Details.Causes[0].Field)
			},
		},
		"malformed DesiredAPIVersion string": {
			req: request{
				Objects:           []runtime.RawExtension{{Raw: []byte("")}},
				DesiredAPIVersion: "foo/bar/baz",
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "failed to parse DesiredAPIVersion", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Equal(t, "unexpected GroupVersion string: foo/bar/baz", resp.Result.Details.Causes[0].Message)
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "DesiredAPIVersion", resp.Result.Details.Causes[0].Field)
			},
		},
		"error while unmarshalling objects from the request": {
			req: request{
				Objects:           []runtime.RawExtension{{Raw: []byte("}{")}},
				DesiredAPIVersion: v1beta1.GroupVersion.String(),
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "failed to unmarshal object at index 0", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Contains(t, resp.Result.Details.Causes[0].Message, "invalid character '}'")
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects[0]", resp.Result.Details.Causes[0].Field)
			},
		},
		"malformed apiVersion string": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`{
  "apiVersion": "foo/bar/baz",
  "kind": "RuleSet"
}`)}},
				DesiredAPIVersion: v1beta1.GroupVersion.String(),
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "failed to unmarshal object at index 0", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Contains(t, resp.Result.Details.Causes[0].Message, "is missing in")
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects[0]", resp.Result.Details.Causes[0].Field)
			},
		},
		"unsupported object kind": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`{
  "apiVersion": "foo/bar",
  "kind": "FooBar"
}`)}},
				DesiredAPIVersion: v1beta1.GroupVersion.String(),
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "expected RuleSet but got FooBar", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Contains(t, resp.Result.Details.Causes[0].Message, "expected RuleSet")
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects[0].kind", resp.Result.Details.Causes[0].Field)
			},
		},
		"rule set is already in the expected version": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`{
  "apiVersion": "heimdall.dadrus.github.com/v1beta1",
  "kind": "RuleSet"
}`)}},
				DesiredAPIVersion: v1beta1.GroupVersion.String(),
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Contains(t, resp.Result.Message, "rule set is already in the expected version")
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Contains(t, resp.Result.Details.Causes[0].Message, "rule set is already in the expected version")
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects[0].apiVersion", resp.Result.Details.Causes[0].Field)
			},
		},
		"failed to convert ruleset due to unexpected source conversion version": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`{
  "apiVersion": "foo/bar",
  "kind": "RuleSet"
}`)}},
				DesiredAPIVersion: v1beta1.GroupVersion.String(),
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "failed to convert rule set", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Equal(t, "conversion error: unexpected source conversion version foo/bar", resp.Result.Details.Causes[0].Message)
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects[0]", resp.Result.Details.Causes[0].Field)
			},
		},
		"failed to convert v1alpha4 ruleset due to unexpected target conversion version": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`{
  "apiVersion": "heimdall.dadrus.github.com/v1alpha4",
  "kind": "RuleSet"
}`)}},
				DesiredAPIVersion: "foo/bar",
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "failed to convert rule set", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Equal(t, "conversion error: unexpected target conversion version foo/bar", resp.Result.Details.Causes[0].Message)
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects[0]", resp.Result.Details.Causes[0].Field)
			},
		},
		"failed to convert v1beta1 ruleset due to unexpected target conversion version": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`{
  "apiVersion": "heimdall.dadrus.github.com/v1beta1",
  "kind": "RuleSet"
}`)}},
				DesiredAPIVersion: "foo/bar",
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Empty(t, resp.ConvertedObjects)
				assert.Equal(t, int32(http.StatusBadRequest), resp.Result.Code)
				assert.Equal(t, "Failure", resp.Result.Status)
				assert.Equal(t, "failed to convert rule set", resp.Result.Message)
				assert.Equal(t, metav1.StatusReasonBadRequest, resp.Result.Reason)
				require.NotNil(t, resp.Result.Details)
				assert.Len(t, resp.Result.Details.Causes, 1)
				assert.Equal(t, "conversion error: unexpected target conversion version foo/bar", resp.Result.Details.Causes[0].Message)
				assert.Equal(t, metav1.CauseTypeFieldValueInvalid, resp.Result.Details.Causes[0].Type)
				assert.Equal(t, "Objects[0]", resp.Result.Details.Causes[0].Field)
			},
		},
		"successful conversion from v1alpha4 to v1beta1": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`
{
  "apiVersion": "heimdall.dadrus.github.com/v1alpha4",
  "kind": "RuleSet",
  "spec": {
    "rules": [
      {
        "id": "public-access",
        "allow_encoded_slashes": "on",
        "match": {
          "routes": [
            { 
              "path": "/pub/*baz",
              "path_params": [
                { "name": "baz", "value": "*foo*", "type": "glob" }
              ]
            }
          ],
          "methods": ["GET", "POST"],
          "hosts": [
            {"value": "foo.bar", "type": "exact"},
            {"value": "*.foo", "type": "wildcard"}
          ],
          "scheme": "https"
        },
        "forward_to": {
          "host": "foo-app.local:8080"
        },
        "execute": [
          { "authorizer": "allow_all_requests" }
        ],
        "on_error": [
          { "error_handler": "default" }
        ]
      }
    ]
  }
}`)}},
				DesiredAPIVersion: v1beta1.GroupVersion.String(),
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Equal(t, int32(http.StatusOK), resp.Result.Code)
				assert.Equal(t, "Success", resp.Result.Status)
				assert.Equal(t, "rule sets converted", resp.Result.Message)
				assert.Empty(t, resp.Result.Reason)
				require.Nil(t, resp.Result.Details)

				assert.Len(t, resp.ConvertedObjects, 1)
				obj := resp.ConvertedObjects[0].Object
				require.IsType(t, &unstructured.Unstructured{}, obj)
				unstr := obj.(*unstructured.Unstructured)
				assert.Equal(t, "heimdall.dadrus.github.com/v1beta1", unstr.GetAPIVersion())
				spec := unstr.Object["spec"]
				require.IsType(t, v1beta1.RuleSetSpec{}, spec)
				ruleSetSpec := spec.(v1beta1.RuleSetSpec)
				assert.Equal(t, v1beta1.RuleSetSpec{
					Rules: []cfgv1beta1.Rule{
						{
							ID:                     "public-access",
							EncodedSlashesHandling: common.EncodedSlashesOn,
							Matcher: cfgv1beta1.Matcher{
								Routes: []cfgv1beta1.Route{
									{
										Path:       "/pub/*baz",
										PathParams: []cfgv1beta1.ParameterMatcher{{Name: "baz", Value: "*foo*", Type: "glob"}},
									},
								},
								Scheme:  "https",
								Methods: []string{"GET", "POST"},
								Hosts:   []string{"foo.bar", "*.foo"},
							},
							Backend: &cfgv1beta1.Backend{
								Host: "foo-app.local:8080",
							},
							Execute: []config.MechanismConfig{
								{"authorizer": "allow_all_requests"},
							},
							ErrorHandler: []config.MechanismConfig{
								{"error_handler": "default"},
							},
						},
					},
				}, ruleSetSpec)
			},
		},
		"successful conversion from v1beta1 to v1alpha4": {
			req: request{
				Objects: []runtime.RawExtension{{Raw: []byte(`
{
  "apiVersion": "heimdall.dadrus.github.com/v1beta1",
  "kind": "RuleSet",
  "spec": {
    "rules": [
      {
        "id": "public-access",
        "allow_encoded_slashes": "on",
        "match": {
          "routes": [
            { 
              "path": "/pub/*baz",
              "path_params": [
                { "name": "baz", "value": "*foo*", "type": "glob" }
              ]
            }
          ],
          "methods": ["GET", "POST"],
          "hosts": [ "foo.bar", "*.foo" ],
          "scheme": "https"
        },
        "forward_to": {
          "host": "foo-app.local:8080"
        },
        "execute": [
          { "authorizer": "allow_all_requests" }
        ],
        "on_error": [
          { "error_handler": "default" }
        ]
      }
    ]
  }
}`)}},
				DesiredAPIVersion: v1alpha4.GroupVersion.String(),
			},
			assert: func(t *testing.T, resp *response) {
				t.Helper()

				assert.Equal(t, int32(http.StatusOK), resp.Result.Code)
				assert.Equal(t, "Success", resp.Result.Status)
				assert.Equal(t, "rule sets converted", resp.Result.Message)
				assert.Empty(t, resp.Result.Reason)
				require.Nil(t, resp.Result.Details)

				assert.Len(t, resp.ConvertedObjects, 1)
				obj := resp.ConvertedObjects[0].Object
				require.IsType(t, &unstructured.Unstructured{}, obj)
				unstr := obj.(*unstructured.Unstructured)
				assert.Equal(t, "heimdall.dadrus.github.com/v1alpha4", unstr.GetAPIVersion())
				spec := unstr.Object["spec"]
				require.IsType(t, v1alpha4.RuleSetSpec{}, spec)
				ruleSetSpec := spec.(v1alpha4.RuleSetSpec)
				assert.Equal(t, v1alpha4.RuleSetSpec{
					Rules: []cfgv1alpha4.Rule{
						{
							ID:                     "public-access",
							EncodedSlashesHandling: common.EncodedSlashesOn,
							Matcher: cfgv1alpha4.Matcher{
								Routes: []cfgv1alpha4.Route{
									{
										Path:       "/pub/*baz",
										PathParams: []cfgv1alpha4.ParameterMatcher{{Name: "baz", Value: "*foo*", Type: "glob"}},
									},
								},
								Scheme:  "https",
								Methods: []string{"GET", "POST"},
								Hosts: []cfgv1alpha4.HostMatcher{
									{
										Value: "foo.bar",
										Type:  "wildcard",
									},
									{
										Value: "*.foo",
										Type:  "wildcard",
									},
								},
							},
							Backend: &cfgv1alpha4.Backend{
								Host: "foo-app.local:8080",
							},
							Execute: []config.MechanismConfig{
								{"authorizer": "allow_all_requests"},
							},
							ErrorHandler: []config.MechanismConfig{
								{"error_handler": "default"},
							},
						},
					},
				}, ruleSetSpec)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			rsv := &rulesetConverter{}

			resp := rsv.Handle(t.Context(), &tc.req)

			tc.assert(t, resp)
		})
	}
}
