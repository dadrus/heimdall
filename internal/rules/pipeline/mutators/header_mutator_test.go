package mutators

import (
	"context"
	"errors"
	"github.com/dadrus/heimdall/internal/rules/pipeline/subject"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/testsupport"
	"github.com/dadrus/heimdall/internal/x"
)

func TestCreateHeaderMutator(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		id     string
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
			uc: "with bad template",
			config: []byte(`
headers:
  bar: "{{ .Subject.ID | foobar }}"
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
			id: "hmut",
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .Subject.ID }}"`),
			assert: func(t *testing.T, err error, mut *headerMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, mut.headers, 2)
				assert.Equal(t, "hmut", mut.HandlerID())

				val, err := mut.headers["foo"].Render(nil, nil)
				require.NoError(t, err)
				assert.Equal(t, "bar", val)

				val, err = mut.headers["bar"].Render(nil, &subject.Subject{ID: "baz"})
				require.NoError(t, err)
				assert.Equal(t, "baz", val)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			// WHEN
			mutator, err := newHeaderMutator(tc.id, conf)

			// THEN
			tc.assert(t, err, mutator)
		})
	}
}

func TestCreateHeaderMutatorFromPrototype(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc              string
		id              string
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *headerMutator, configured *headerMutator)
	}{
		{
			uc: "no new configuration provided",
			id: "hmut1",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			assert: func(t *testing.T, err error, prototype *headerMutator, configured *headerMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "hmut1", configured.HandlerID())
			},
		},
		{
			uc: "configuration without headers provided",
			id: "hmut2",
			prototypeConfig: []byte(`
headers:
  foo: bar
`),
			config: []byte(``),
			assert: func(t *testing.T, err error, prototype *headerMutator, configured *headerMutator) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
				assert.Equal(t, "hmut2", configured.HandlerID())
			},
		},
		{
			uc: "new headers provided",
			id: "hmut3",
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
				assert.Equal(t, "hmut3", configured.HandlerID())

				val, err := configured.headers["bar"].Render(nil, nil)
				require.NoError(t, err)
				assert.Equal(t, "foo", val)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			prototype, err := newHeaderMutator(tc.id, pc)
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
		id               string
		config           []byte
		configureContext func(t *testing.T, ctx *mocks.MockContext)
		createSubject    func(t *testing.T) *subject.Subject
		assert           func(t *testing.T, err error)
	}{
		{
			uc: "with nil subject",
			id: "hmut1",
			config: []byte(`
headers:
  foo: bar
  bar: "{{ .Subject.ID }}"
`),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrInternal)
				assert.Contains(t, err.Error(), "'nil' subject")

				var identifier interface{ HandlerID() string }
				require.True(t, errors.As(err, &identifier))
				assert.Equal(t, "hmut1", identifier.HandlerID())
			},
		},
		{
			uc: "with all preconditions satisfied",
			config: []byte(`
headers:
  foo: "{{ .Subject.Attributes.bar }}"
  bar: "{{ .Subject.ID }}"
  baz: bar
`),
			configureContext: func(t *testing.T, ctx *mocks.MockContext) {
				t.Helper()

				ctx.On("AddHeaderForUpstream", "foo", "baz")
				ctx.On("AddHeaderForUpstream", "bar", "FooBar")
				ctx.On("AddHeaderForUpstream", "baz", "bar")
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

			mutator, err := newHeaderMutator(tc.id, conf)
			require.NoError(t, err)

			// WHEN
			err = mutator.Execute(mctx, sub)

			// THEN
			tc.assert(t, err)

			mctx.AssertExpectations(t)
		})
	}
}
