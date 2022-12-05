package v1alpha1

import (
	"context"
	"net/http"
	"net/http/httptest"
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
  "apiVersion": "heimdall.dadrus.github.com/v1alpha1",
  "items": [{
      "apiVersion": "heimdall.dadrus.github.com/v1alpha1",
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
            "matching_strategy": "glob",
            "url": "http://127.0.0.1:9090/foobar/<{foos*}>",
            "upstream": "http://foobar"
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
		require.NoError(s.T(), err)

		w.WriteHeader(http.StatusOK)
	}))

	var err error

	s.cl, err = NewClient(&rest.Config{Host: s.srv.URL})
	require.NoError(s.T(), err)
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
	assert.Equal(t, "heimdall.dadrus.github.com/v1alpha1", ruleSet.APIVersion)
	assert.Equal(t, "test-rule-set", ruleSet.Name)
	assert.Equal(t, "foo", ruleSet.Namespace)
	assert.Equal(t, "foobar", ruleSet.Spec.AuthClassName)
	assert.Len(t, ruleSet.Spec.Rules, 1)

	rule := ruleSet.Spec.Rules[0]
	assert.Equal(t, "test:rule", rule.ID)
	assert.Equal(t, "glob", rule.MatchingStrategy)
	assert.Equal(t, "http://127.0.0.1:9090/foobar/<{foos*}>", rule.URL)
	assert.Empty(t, rule.Methods)
	assert.Empty(t, rule.ErrorHandler)
	assert.Equal(t, "http://foobar", rule.Upstream)
	assert.Len(t, rule.Execute, 2)
	assert.Equal(t, "test_authn", rule.Execute[0]["authenticator"])
	assert.Equal(t, "test_authz", rule.Execute[1]["authorizer"])
}

func (s *ClientTestSuite) TestRuleSetsList() {
	// WHEN
	rls, err := s.cl.RuleSetRepository("foo").List(context.Background(), metav1.ListOptions{})

	// THEN
	require.NoError(s.T(), err)
	verifyRuleSetList(s.T(), rls)
}

func (s *ClientTestSuite) TestRuleSetsWatch() {
	// WHEN
	watcher, err := s.cl.RuleSetRepository("foo").Watch(context.Background(), metav1.ListOptions{})

	// THEN
	require.NoError(s.T(), err)

	evtChain := watcher.ResultChan()

	evt := <-evtChain

	assert.Equal(s.T(), watch.Added, evt.Type)
	assert.IsType(s.T(), &RuleSetList{}, evt.Object)
	// nolint: forcetypeassert
	verifyRuleSetList(s.T(), evt.Object.(*RuleSetList))
}
