package template_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template/mocks"
)

type stringerValue string

func (v stringerValue) String() string {
	return string(v)
}

func TestTemplateURLEncodeFunction(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		raw      string
		values   map[string]any
		expected string
	}{
		"encodes string value": {
			raw:      `{{ urlenc .Value }}`,
			values:   map[string]any{"Value": "foo bar/baz?x=1&y=2"},
			expected: "foo+bar%2Fbaz%3Fx%3D1%26y%3D2",
		},
		"encodes stringer value": {
			raw:      `{{ urlenc .Value }}`,
			values:   map[string]any{"Value": stringerValue("foo bar")},
			expected: "foo+bar",
		},
		"unsupported value renders empty string": {
			raw:      `{{ urlenc .Value }}`,
			values:   map[string]any{"Value": 42},
			expected: "",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			tpl, err := template.New(tc.raw)
			require.NoError(t, err)

			got, err := tpl.Render(tc.values)
			require.NoError(t, err)

			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestTemplateAtIndex(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		val  any
		expr string
		res  string
		err  string
	}{
		{val: []int{1, 2, 3, 4}, expr: "{{ atIndex 0 .Slice }}", res: "1"},
		{val: []int{1, 2, 3, 4}, expr: "{{ atIndex 2 .Slice }}", res: "3"},
		{val: []int{1, 2, 3, 4}, expr: "{{ atIndex -1 .Slice }}", res: "4"},
		{val: []int{1, 2, 3, 4}, expr: "{{ atIndex -3 .Slice }}", res: "2"},
		{
			val: []int{1, 2, 3, 4}, expr: "{{ atIndex 6 .Slice }}",
			err: "cannot at(6), position is outside of the list boundaries",
		},
		{
			val: []int{1, 2, 3, 4}, expr: "{{ atIndex -6 .Slice }}",
			err: "cannot at(-6), position is outside of the list boundaries",
		},
		{val: "foo", expr: "{{ atIndex 1 .Slice }}", err: "cannot find at on type string"},
		{val: []string{}, expr: "{{ atIndex 0 .Slice }}", res: "<no value>"},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			tmpl, err := template.New(tc.expr)
			require.NoError(t, err)

			res, err := tmpl.Render(map[string]any{"Slice": tc.val})

			if len(tc.err) != 0 {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.err)
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestTemplateSecret(t *testing.T) {
	t.Parallel()

	ref := template.SecretReference{
		Source:   "k8s",
		Selector: "api-key",
	}

	for uc, tc := range map[string]struct {
		raw    string
		setup  func(t *testing.T, sm *mocks.SecretStoreMock)
		values map[string]any
		assert func(t *testing.T, value string, err error)
	}{
		"renders registered secret": {
			raw: `{{ secret "k8s" "api-key" }}`,
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil)
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", value)
			},
		},
		"registers duplicate secret only once": {
			raw: `{{ secret "k8s" "api-key" }} {{ secret "k8s" "api-key" }}`,
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil).Twice()
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo foo", value)
			},
		},
		"registers secret inside if branch": {
			raw: `{{ if .Enabled }}{{ secret "k8s" "api-key" }}{{ end }}`,
			values: map[string]any{
				"Enabled": true,
			},
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil)
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", value)
			},
		},
		"registers secret inside if else branch": {
			raw: `{{ if .Enabled }}disabled{{ else }}{{ secret "k8s" "api-key" }}{{ end }}`,
			values: map[string]any{
				"Enabled": false,
			},
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil)
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", value)
			},
		},
		"registers secret inside range branch": {
			raw: `{{ range .Items }}{{ secret "k8s" "api-key" }}{{ end }}`,
			values: map[string]any{
				"Items": []string{"a", "b"},
			},
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil).Twice()
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foofoo", value)
			},
		},
		"registers secret inside range else branch": {
			raw: `{{ range .Items }}unused{{ else }}{{ secret "k8s" "api-key" }}{{ end }}`,
			values: map[string]any{
				"Items": []string{},
			},
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil)
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", value)
			},
		},
		"registers secret inside with branch": {
			raw: `{{ with .Value }}{{ secret "k8s" "api-key" }}{{ end }}`,
			values: map[string]any{
				"Value": "present",
			},
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil)
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", value)
			},
		},
		"registers secret inside with else branch": {
			raw: `{{ with .Value }}unused{{ else }}{{ secret "k8s" "api-key" }}{{ end }}`,
			values: map[string]any{
				"Value": "",
			},
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil)
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", value)
			},
		},
		"registers secret inside named template": {
			raw: `{{ define "apiKey" }}{{ secret "k8s" "api-key" }}{{ end }}{{ template "apiKey" . }}`,
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("foo", nil)
			},
			assert: func(t *testing.T, value string, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, "foo", value)
			},
		},
		"returns register secret error": {
			raw: `{{ secret "k8s" "api-key" }}`,
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(assert.AnError)
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
				require.ErrorIs(t, err, assert.AnError)
			},
		},
		"returns get secret error": {
			raw: `{{ secret "k8s" "api-key" }}`,
			setup: func(t *testing.T, sm *mocks.SecretStoreMock) {
				t.Helper()

				sm.EXPECT().RegisterSecret(ref).Return(nil)
				sm.EXPECT().GetSecret(ref).Return("", assert.AnError)
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, template.ErrTemplateRender)
				require.ErrorIs(t, err, assert.AnError)
			},
		},
		"rejects dynamic source": {
			raw: `{{ secret .Source "api-key" }}`,
			setup: func(t *testing.T, _ *mocks.SecretStoreMock) {
				t.Helper()
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
			},
		},
		"rejects dynamic selector": {
			raw: `{{ secret "k8s" .Selector }}`,
			setup: func(t *testing.T, _ *mocks.SecretStoreMock) {
				t.Helper()
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
			},
		},
		"rejects piped source": {
			raw: `{{ secret (print "k8s") "api-key" }}`,
			setup: func(t *testing.T, _ *mocks.SecretStoreMock) {
				t.Helper()
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
			},
		},
		"rejects piped selector": {
			raw: `{{ secret "k8s" (print "api-key") }}`,
			setup: func(t *testing.T, _ *mocks.SecretStoreMock) {
				t.Helper()
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
			},
		},
		"rejects missing selector": {
			raw: `{{ secret "k8s" }}`,
			setup: func(t *testing.T, _ *mocks.SecretStoreMock) {
				t.Helper()
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
			},
		},
		"rejects additional argument": {
			raw: `{{ secret "k8s" "api-key" "unexpected" }}`,
			setup: func(t *testing.T, _ *mocks.SecretStoreMock) {
				t.Helper()
			},
			assert: func(t *testing.T, _ string, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrConfiguration)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			sm := mocks.NewSecretStoreMock(t)
			tc.setup(t, sm)

			tpl, err := template.New(tc.raw, template.WithSecretStore(sm))

			var rendered string
			if err == nil {
				rendered, err = tpl.Render(tc.values)
			}

			tc.assert(t, rendered, err)
		})
	}

	t.Run("panics when secret function is used without secret store", func(t *testing.T) {
		t.Parallel()

		require.Panics(t, func() {
			_, _ = template.New(`{{ secret "k8s" "api-key" }}`)
		})
	})

	t.Run("does not panic when secrets are not used", func(t *testing.T) {
		t.Parallel()

		tpl, err := template.New(`hello {{ .Name }}`)
		require.NoError(t, err)

		value, err := tpl.Render(map[string]any{"Name": "foo"})
		require.NoError(t, err)

		assert.Equal(t, "hello foo", value)
	})
}
