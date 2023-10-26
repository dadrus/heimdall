package admissioncontroller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dadrus/heimdall/internal/config"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha2"
	"github.com/dadrus/heimdall/internal/rules/rule/mocks"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestControllerLifecycle(t *testing.T) {
	t.Parallel()

	authClass := "test"

	reviewReq := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{Kind: "AdmissionReview", APIVersion: "admission.k8s.io/v1"},
		Request: &admissionv1.AdmissionRequest{
			UID:             "ce409862-eae0-4704-b7d5-46634efdaf9b",
			Namespace:       "test",
			Name:            "test-rules",
			Operation:       admissionv1.Create,
			Kind:            metav1.GroupVersionKind{Group: v1alpha2.GroupName, Version: v1alpha2.GroupVersion, Kind: "RuleSet"},
			Resource:        metav1.GroupVersionResource{Group: v1alpha2.GroupName, Version: v1alpha2.GroupVersion, Resource: "rulesets"},
			RequestKind:     &metav1.GroupVersionKind{Group: v1alpha2.GroupName, Version: v1alpha2.GroupVersion, Kind: "RuleSet"},
			RequestResource: &metav1.GroupVersionResource{Group: v1alpha2.GroupName, Version: v1alpha2.GroupVersion, Resource: "rulesets"},
		},
	}

	for _, tc := range []struct {
		uc               string
		request          func(t *testing.T, URL string) *http.Request
		setupRuleFactory func(t *testing.T, factory *mocks.FactoryMock)
		assert           func(t *testing.T, resp *http.Response)
	}{
		{
			uc: "unsupported review request kind",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				reviewReq.Request.Kind.Kind = "FooBar"

				data, err := json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL, bytes.NewReader(data))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.False(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusBadRequest, int(status.Code))
				assert.Equal(t, "Failure", status.Status)
				assert.Contains(t, status.Message, "failed parsing RuleSet")
				assert.Contains(t, status.Reason, "only rule sets")
				require.NotNil(t, status.Details)
				require.Len(t, status.Details.Causes, 1)
				assert.Contains(t, status.Details.Causes[0].Message, "only rule sets")
			},
		},
		{
			uc: "RuleSet filtered",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				ruleSet := v1alpha2.RuleSet{
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
					Spec: v1alpha2.RuleSetSpec{AuthClassName: "foo"},
				}
				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				reviewReq.Request.Object.Raw = data

				data, err = json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL, bytes.NewReader(data))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.True(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusOK, int(status.Code))
				assert.Equal(t, "Success", status.Status)
				assert.Contains(t, status.Message, "RuleSet ignored")
			},
		},
		{
			uc: "RuleSet validation fails",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				ruleSet := v1alpha2.RuleSet{
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
						AuthClassName: authClass,
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
				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				reviewReq.Request.Object.Raw = data

				data, err = json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL, bytes.NewReader(data))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			setupRuleFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().CreateRule("1alpha2", mock.Anything, mock.Anything).
					Once().Return(nil, errors.New("Test error"))
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.False(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusForbidden, int(status.Code))
				assert.Equal(t, "Failure", status.Status)
				assert.Contains(t, status.Message, "RuleSet invalid")
				assert.Contains(t, status.Reason, "Test error")
				require.NotNil(t, status.Details)
				require.Len(t, status.Details.Causes, 1)
				assert.Contains(t, status.Details.Causes[0].Message, "Test error")
			},
		},
		{
			uc: "successful RuleSet validation",
			request: func(t *testing.T, URL string) *http.Request {
				t.Helper()

				ruleSet := v1alpha2.RuleSet{
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
						AuthClassName: authClass,
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
				data, err := json.Marshal(&ruleSet)
				require.NoError(t, err)

				reviewReq.Request.Object.Raw = data

				data, err = json.Marshal(&reviewReq)
				require.NoError(t, err)

				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, URL, bytes.NewReader(data))
				require.NoError(t, err)
				req.Header.Set("Content-Type", "application/json")

				return req
			},
			setupRuleFactory: func(t *testing.T, factory *mocks.FactoryMock) {
				t.Helper()

				factory.EXPECT().CreateRule("1alpha2", mock.Anything, mock.Anything).
					Once().Return(nil, nil)
			},
			assert: func(t *testing.T, resp *http.Response) {
				t.Helper()

				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

				var reviewResp admissionv1.AdmissionReview
				err := json.NewDecoder(resp.Body).Decode(&reviewResp)
				require.NoError(t, err)

				vResp := reviewResp.Response
				require.NotNil(t, vResp)
				assert.True(t, vResp.Allowed)

				status := vResp.Result
				assert.NotNil(t, status)
				assert.Equal(t, http.StatusOK, int(status.Code))
				assert.Equal(t, "Success", status.Status)
				assert.Contains(t, status.Message, "RuleSet valid")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			reviewReq.Request.Kind.Kind = "RuleSet"
			reviewReq.Request.Object.Raw = nil

			port, err := testsupport.GetFreePort()
			require.NoError(t, err)
			listeningAddress = fmt.Sprintf("127.0.0.1:%d", port)

			setupMock := x.IfThenElse(
				tc.setupRuleFactory != nil,
				tc.setupRuleFactory,
				func(t *testing.T, _ *mocks.FactoryMock) { t.Helper() },
			)

			rf := mocks.NewFactoryMock(t)
			setupMock(t, rf)

			controller := New(
				nil,
				log.Logger,
				authClass,
				rf,
			)

			serviceAddress := fmt.Sprintf("http://%s/validate-ruleset", listeningAddress)

			err = controller.Start(context.TODO())
			require.NoError(t, err)

			time.Sleep(50 * time.Millisecond)

			defer controller.Stop(context.TODO())

			client := &http.Client{Transport: &http.Transport{}}

			// WHEN
			resp, err := client.Do(tc.request(t, serviceAddress))

			// THEN
			require.NoError(t, err)

			defer resp.Body.Close()

			tc.assert(t, resp)
			rf.AssertExpectations(t)
		})
	}
}
