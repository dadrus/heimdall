package v1beta1

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest/fake"
	"k8s.io/utils/ptr"

	"github.com/dadrus/heimdall/internal/x"
)

func TestRepositoryList(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		namespace string
		opts      metav1.ListOptions
		resp      *http.Response
		assert    func(t *testing.T, req *http.Request)
	}{
		"with error": {
			namespace: "foo",
			assert:    func(t *testing.T, _ *http.Request) { t.Helper() },
		},
		"successful without options": {
			namespace: "bar",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/bar/rulesets", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Empty(t, req.URL.Query())
			},
		},
		"successful with options": {
			namespace: "foo",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			opts: metav1.ListOptions{
				TimeoutSeconds: ptr.To[int64](5),
				Limit:          10,
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/foo/rulesets", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Len(t, req.URL.Query(), 3)
				assert.Equal(t, "10", req.URL.Query().Get("limit"))
				assert.Equal(t, "5s", req.URL.Query().Get("timeout"))
				assert.Equal(t, "5", req.URL.Query().Get("timeoutSeconds"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			restClient := &fake.RESTClient{
				GroupVersion:         GroupVersion,
				NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
				Err:                  x.IfThenElse(tc.resp == nil, errors.New("test error"), nil),
				Resp:                 tc.resp,
			}

			repo := ruleSetRepository{cl: restClient, ns: tc.namespace}

			res, err := repo.List(t.Context(), tc.opts)
			if tc.resp == nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				tc.assert(t, restClient.Req)
			}
		})
	}
}

func TestRepositoryWatch(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		namespace string
		opts      metav1.ListOptions
		resp      *http.Response
		assert    func(t *testing.T, req *http.Request)
	}{
		"with error": {
			namespace: "foo",
			assert:    func(t *testing.T, _ *http.Request) { t.Helper() },
		},
		"successful without options": {
			namespace: "bar",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/bar/rulesets", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Len(t, req.URL.Query(), 1)
				assert.Equal(t, "true", req.URL.Query().Get("watch"))
			},
		},
		"successful with options": {
			namespace: "foo",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			opts: metav1.ListOptions{
				TimeoutSeconds: ptr.To[int64](5),
				Limit:          10,
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/foo/rulesets", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Len(t, req.URL.Query(), 4)
				assert.Equal(t, "true", req.URL.Query().Get("watch"))
				assert.Equal(t, "10", req.URL.Query().Get("limit"))
				assert.Equal(t, "5s", req.URL.Query().Get("timeout"))
				assert.Equal(t, "5", req.URL.Query().Get("timeoutSeconds"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			restClient := &fake.RESTClient{
				GroupVersion:         GroupVersion,
				NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
				Err:                  x.IfThenElse(tc.resp == nil, errors.New("test error"), nil),
				Resp:                 tc.resp,
			}

			repo := ruleSetRepository{cl: restClient, ns: tc.namespace}

			res, err := repo.Watch(t.Context(), tc.opts)
			if tc.resp == nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				tc.assert(t, restClient.Req)
			}
		})
	}
}

func TestRepositoryGet(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		namespace string
		key       types.NamespacedName
		opts      metav1.GetOptions
		resp      *http.Response
		assert    func(t *testing.T, req *http.Request)
	}{
		"with error": {
			namespace: "baz",
			key:       types.NamespacedName{Namespace: "foo", Name: "bar"},
			assert:    func(t *testing.T, _ *http.Request) { t.Helper() },
		},
		"successful without options": {
			namespace: "baz",
			key:       types.NamespacedName{Namespace: "bar", Name: "foo"},
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/bar/rulesets/foo", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Empty(t, req.URL.Query())
			},
		},
		"successful with options": {
			namespace: "foo",
			key:       types.NamespacedName{Namespace: "foo", Name: "bar"},
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			opts: metav1.GetOptions{
				ResourceVersion: "v10alpha1",
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/foo/rulesets/bar", req.URL.Path)
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Len(t, req.URL.Query(), 1)
				assert.Equal(t, "v10alpha1", req.URL.Query().Get("resourceVersion"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			restClient := &fake.RESTClient{
				GroupVersion:         GroupVersion,
				NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
				Err:                  x.IfThenElse(tc.resp == nil, errors.New("test error"), nil),
				Resp:                 tc.resp,
			}

			repo := ruleSetRepository{cl: restClient, ns: tc.namespace}

			res, err := repo.Get(t.Context(), tc.key, tc.opts)
			if tc.resp == nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				tc.assert(t, restClient.Req)
			}
		})
	}
}

func TestRepositoryPatchStatus(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		namespace string
		opts      metav1.PatchOptions
		resp      *http.Response
		patchErr  error
		assert    func(t *testing.T, req *http.Request)
	}{
		"with error while getting patch data": {
			namespace: "baz",
			patchErr:  errors.New("patch error"),
			assert:    func(t *testing.T, _ *http.Request) { t.Helper() },
		},
		"successful without options": {
			namespace: "baz",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/baz/rulesets/foo-rule-set/status", req.URL.Path)
				assert.Equal(t, http.MethodPatch, req.Method)
				assert.Empty(t, req.URL.Query())
			},
		},
		"successful with options": {
			namespace: "foo",
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			},
			opts: metav1.PatchOptions{
				Force: ptr.To[bool](true),
			},
			assert: func(t *testing.T, req *http.Request) {
				t.Helper()

				assert.Equal(t, "/namespaces/foo/rulesets/foo-rule-set/status", req.URL.Path)
				assert.Equal(t, http.MethodPatch, req.Method)
				assert.Len(t, req.URL.Query(), 1)
				assert.Equal(t, "true", req.URL.Query().Get("force"))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			restClient := &fake.RESTClient{
				GroupVersion:         GroupVersion,
				NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
				Err:                  x.IfThenElse(tc.resp == nil, errors.New("test error"), nil),
				Resp:                 tc.resp,
			}
			repo := ruleSetRepository{cl: restClient, ns: tc.namespace}
			patch := NewPatchMock(t)

			if tc.patchErr != nil {
				patch.EXPECT().Data().Return(nil, tc.patchErr)
			} else {
				patch.EXPECT().Data().Return([]byte(`{}`), nil)
				patch.EXPECT().ResourceName().Return("foo-rule-set")
				patch.EXPECT().Type().Return(types.JSONPatchType)
			}

			res, err := repo.PatchStatus(t.Context(), patch, tc.opts)
			if tc.resp == nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				tc.assert(t, restClient.Req)
			}
		})
	}
}
