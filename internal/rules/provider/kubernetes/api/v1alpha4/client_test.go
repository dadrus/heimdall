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

package v1alpha4

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
)

const watchResponse = `{
  "type": "ADDED",
  "object": ` + response + `
}
`

const response = `{
  "apiVersion": "heimdall.dadrus.github.com/v1alpha4",
  "items": [{
      "apiVersion": "heimdall.dadrus.github.com/v1alpha4",
      "kind": "RuleSet",
      "metadata": {
        "name": "test-rule-set",
        "namespace": "foo",
        "resourceVersion": "684780",
        "uid": "3c49d7b6-710d-446d-95da-334bc2c1072b"
      },
      "spec": {
        "authClassName": "foobar",
        "rules": [{
            "execute": [
              { "authenticator": "test_authn" },
              { "authorizer": "test_authz" }
            ],
            "id": "test:rule",
            "match": {
              "routes": [
                {
                  "path": "/foobar/*foo",
                  "path_params": [{ "name": "foo", "type": "glob", "value": "foos*" }]
                },
                {
                  "path": "/foobar/baz"
                }
              ],
              "scheme": "http",
              "hosts": [ 
                {"type": "exact","value": "127.0.0.1"}, 
                {"type": "glob","value": "172.*.*.1"} 
              ],
              "methods": ["GET", "POST"]
            },
            "forward_to": {
              "host": "foo.bar",
              "rewrite": {
			    "scheme": "https",
				"strip_path_prefix": "/foo",
				"add_path_prefix": "/baz",
				"strip_query_parameters": ["boo"]
			  }
			}
          }
        ]
      }
    }
  ],
  "kind": "RuleSetList",
  "metadata": {
    "resourceVersion": "685324"
  }
}`

type ClientTestSuite struct {
	suite.Suite

	srv *httptest.Server
	cl  Client
}

func (s *ClientTestSuite) SetupSuite() {
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		qWatch := r.URL.Query().Get("watch")

		var err error

		if qWatch == "true" {
			_, err = w.Write([]byte(watchResponse))
		} else {
			_, err = w.Write([]byte(response))
		}

		s.NoError(err)

		w.WriteHeader(http.StatusOK)
	}))

	var err error

	s.cl, err = NewClient(&rest.Config{Host: s.srv.URL})
	s.Require().NoError(err)
}

func (s *ClientTestSuite) TearDownSuite() {
	s.srv.Close()
}

func TestClientTestSuite(t *testing.T) {
	suite.Run(t, new(ClientTestSuite))
}

func verifyRuleSetList(t *testing.T, rls *RuleSetList) {
	t.Helper()

	require.NotNil(t, rls)
	assert.Len(t, rls.Items, 1)

	ruleSet := rls.Items[0]
	assert.Equal(t, "RuleSet", ruleSet.Kind)
	assert.Equal(t, "heimdall.dadrus.github.com/v1alpha4", ruleSet.APIVersion)
	assert.Equal(t, "test-rule-set", ruleSet.Name)
	assert.Equal(t, "foo", ruleSet.Namespace)
	assert.Equal(t, "foobar", ruleSet.Spec.AuthClassName)
	assert.Len(t, ruleSet.Spec.Rules, 1)

	rule := ruleSet.Spec.Rules[0]
	assert.Equal(t, "test:rule", rule.ID)
	assert.Len(t, rule.Matcher.Routes, 2)
	assert.Equal(t, "/foobar/*foo", rule.Matcher.Routes[0].Path)
	assert.Len(t, rule.Matcher.Routes[0].PathParams, 1)
	assert.Equal(t, "foo", rule.Matcher.Routes[0].PathParams[0].Name)
	assert.Equal(t, "glob", rule.Matcher.Routes[0].PathParams[0].Type)
	assert.Equal(t, "foos*", rule.Matcher.Routes[0].PathParams[0].Value)
	assert.Equal(t, "/foobar/baz", rule.Matcher.Routes[1].Path)
	assert.Equal(t, "http", rule.Matcher.Scheme)
	assert.Len(t, rule.Matcher.Hosts, 2)
	assert.Equal(t, "127.0.0.1", rule.Matcher.Hosts[0].Value)
	assert.Equal(t, "exact", rule.Matcher.Hosts[0].Type)
	assert.Equal(t, "172.*.*.1", rule.Matcher.Hosts[1].Value)
	assert.Equal(t, "glob", rule.Matcher.Hosts[1].Type)
	assert.ElementsMatch(t, rule.Matcher.Methods, []string{"GET", "POST"})
	assert.Empty(t, rule.ErrorHandler)
	assert.Equal(t, "https://foo.bar/baz/bar?foo=bar", rule.Backend.CreateURL(&url.URL{
		Scheme:   "http",
		Host:     "bar.foo:8888",
		Path:     "/foo/bar",
		RawQuery: url.Values{"boo": []string{"foo"}, "foo": []string{"bar"}}.Encode(),
	}).String())
	assert.Len(t, rule.Execute, 2)
	assert.Equal(t, "test_authn", rule.Execute[0]["authenticator"])
	assert.Equal(t, "test_authz", rule.Execute[1]["authorizer"])
}

func (s *ClientTestSuite) TestRuleSetsList() {
	// WHEN
	rls, err := s.cl.RuleSetRepository("foo").List(context.Background(), metav1.ListOptions{})

	// THEN
	s.Require().NoError(err)
	verifyRuleSetList(s.T(), rls)
}

func (s *ClientTestSuite) TestRuleSetsWatch() {
	// WHEN
	watcher, err := s.cl.RuleSetRepository("foo").Watch(context.Background(), metav1.ListOptions{})

	// THEN
	s.Require().NoError(err)

	evtChain := watcher.ResultChan()

	evt := <-evtChain

	s.Equal(watch.Added, evt.Type)
	s.IsType(&RuleSetList{}, evt.Object)
	// nolint: forcetypeassert
	verifyRuleSetList(s.T(), evt.Object.(*RuleSetList))
}
