package mutators

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/pipeline/template"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateHeaderMutator(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		config []byte
		assert func(t *testing.T, err error, mut *headerMutator)
	}{
		{
			uc: "without configuration",
			assert: func(t *testing.T, err error, mut *headerMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no header")
			},
		},
		{
			uc:     "without header configuration",
			config: []byte(``),
			assert: func(t *testing.T, err error, mut *headerMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "no header")
			},
		},
		{
			uc: "with unsupported attributes",
			config: []byte(`
headers:
  foo: bar
foo: bar
`),
			assert: func(t *testing.T, err error, mut *headerMutator) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed to unmarshal")
			},
		},
		{
			uc: "with valid config",
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .ID }}"`),
			assert: func(t *testing.T, err error, mut *headerMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, mut.headers, 2)
				assert.Equal(t, template.Template("bar"), mut.headers["foo"])
				assert.Equal(t, template.Template("{{ .ID }}"), mut.headers["bar"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			mutator, err := newHeaderMutator(conf)

			// THEN
			tc.assert(t, err, mutator)
		})
	}
}

func TestCreateHeaderMutatorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *headerMutator, configured *headerMutator)
	}{
		{
			uc: "no new configuration provided",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype *headerMutator, configured *headerMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "configuration without headers provided",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *headerMutator, configured *headerMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		{
			uc: "new headers provided",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			config: []byte(`
headers:
  bar: foo
`),
			assert: func(t *testing.T, err error, prototype *headerMutator, configured *headerMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.NotEqual(t, prototype, configured)
				require.NotNil(t, configured)
				assert.NotEmpty(t, configured.headers)
				assert.Equal(t, template.Template("foo"), configured.headers["bar"])
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newHeaderMutator(pc)
			require.NoError(t, err)

			// WHEN
			mutator, err := prototype.WithConfig(conf)

			// THEN
			headerMut, ok := mutator.(*headerMutator)
			require.True(t, ok)

			tc.assert(t, err, prototype, headerMut)
		})
	}
}

func TestHeaderMutatorExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc               string
		config           []byte
		configureContext func(t *testing.T, ctx *mocks.MockContext)
		createSubject    func(t *testing.T) *subject.Subject
		assert           func(t *testing.T, err error)
	}{
		{
			uc: "with nil subject",
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .ID }}"
`),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")
			},
		},
		{
			uc: "with bad template",
			config: []byte(`
headers:
  bar: "{{ .ID | foobar }}"
`),
			createSubject: func(t *testing.T) *subject.Subject {
				t.Helper()

				return &subject.Subject{ID: "FooBar"}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "failed to render")
			},
		},
		{
			uc: "with all preconditions satisfied",
			config: []byte(`
headers:
  foo: "{{ .Attributes.bar }}"
  bar: "{{ .ID }}"
  baz: bar
`),
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("AddResponseHeader", "foo", "baz")
				ctx.On("AddResponseHeader", "bar", "FooBar")
				ctx.On("AddResponseHeader", "baz", "bar")
			},
			createSubject: func(t *testing.T) *subject.Subject {
				t.Helper()

				return &subject.Subject{ID: "FooBar", Attributes: map[string]any{"bar": "baz"}}
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			createSubject := x.IfThenElse(tc.createSubject != nil,
				tc.createSubject,
				func(t *testing.T) *subject.Subject {
					t.Helper()

					return nil
				})

			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, ctx *mocks.MockContext) { t.Helper() })

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			mctx := &mocks.MockContext{}
			mctx.On("AppContext").Return(context.Background())

			sub := createSubject(t)

			configureContext(t, mctx)

			mutator, err := newHeaderMutator(conf)
			require.NoError(t, err)

			// WHEN
			err = mutator.Execute(mctx, sub)

			// THEN
			tc.assert(t, err)

			mctx.AssertExpectations(t)
		})
	}
}
