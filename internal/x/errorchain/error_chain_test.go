package errorchain_test

import (
	"encoding/xml"
	"errors"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	errTest1 = errors.New("test error 1")
	errTest2 = errors.New("test error 2")
)

type errCtx struct{}

func (e *errCtx) Foo() string { return "foo" }

type testError struct{}

func (e *testError) Error() string { return "test error 3" }
func (e *testError) Bar() string   { return "bar" }

type barAspect struct{}

func (a *barAspect) Bar() string { return "aspect bar" }

type namedCtx struct {
	name string
}

func (c *namedCtx) Foo() string { return c.name }

func TestErrorChainNew(t *testing.T) {
	t.Parallel()

	err := errorchain.New(errTest1)

	require.Error(t, err)
	require.ErrorIs(t, err, errTest1)
	assert.Equal(t, errTest1.Error(), err.Error())
}

func TestErrorChainNewWithMessage(t *testing.T) {
	t.Parallel()

	err := errorchain.NewWithMessage(errTest1, "foobar")

	require.Error(t, err)
	require.ErrorIs(t, err, errTest1)
	assert.Equal(t, errTest1.Error()+": foobar", err.Error())
}

func TestErrorChainNewWithFormattedMessage(t *testing.T) {
	t.Parallel()

	err := errorchain.NewWithMessagef(errTest1, "%s%s", "foo", "bar")

	require.Error(t, err)
	require.ErrorIs(t, err, errTest1)
	assert.Equal(t, errTest1.Error()+": foobar", err.Error())
}

func TestErrorChainNewWithCause(t *testing.T) {
	t.Parallel()

	type Fooer interface{ Foo() string }

	err := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	require.Error(t, err)
	require.ErrorIs(t, err, errTest1)
	require.ErrorIs(t, err, errTest2)
	assert.Equal(t, errTest1.Error()+": foo: "+errTest2.Error(), err.Error())
	assert.ElementsMatch(t, []error{errTest1, errTest2}, err.Errors())

	var fooer Fooer
	require.NotErrorAs(t, err, &fooer)
}

func TestErrorChainErrorAsFindsAspectFromTopLevel(t *testing.T) {
	t.Parallel()

	type Fooer interface{ Foo() string }

	err := errorchain.NewWithMessage(errTest1, "foo").
		WithAspects(&errCtx{}).
		CausedBy(errTest2)

	var fooer Fooer
	require.ErrorAs(t, err, &fooer)
	assert.Equal(t, "foo", fooer.Foo())
}

func TestErrorChainErrorAsFindsAspectFromCauseLevel(t *testing.T) {
	t.Parallel()

	type Fooer interface{ Foo() string }

	err := errorchain.NewWithMessage(errTest1, "foo").
		CausedBy(errTest2).
		WithAspects(&errCtx{})

	var fooer Fooer
	require.ErrorAs(t, err, &fooer)
	assert.Equal(t, "foo", fooer.Foo())
}

func TestErrorChainErrorAsFindsAspectsFromDifferentLevels(t *testing.T) {
	t.Parallel()

	type Fooer interface{ Foo() string }

	type Barer interface{ Bar() string }

	err := errorchain.NewWithMessage(errTest1, "foo").
		WithAspects(&errCtx{}).
		CausedBy(errTest2).
		CausedBy(errors.New("test error 4")).
		WithAspects(&testError{})

	var fooer Fooer
	require.ErrorAs(t, err, &fooer)
	assert.Equal(t, "foo", fooer.Foo())

	var barer Barer
	require.ErrorAs(t, err, &barer)
	assert.Equal(t, "bar", barer.Bar())
}

func TestErrorChainErrorAsReturnsFirstMatchingAspect(t *testing.T) {
	t.Parallel()

	type Fooer interface{ Foo() string }

	err := errorchain.NewWithMessage(errTest1, "foo").
		WithAspects(&namedCtx{name: "first"}).
		CausedBy(errTest2).
		WithAspects(&namedCtx{name: "second"})

	var fooer Fooer
	require.ErrorAs(t, err, &fooer)
	assert.Equal(t, "first", fooer.Foo())
}

func TestErrorChainErrorAsPanicsForConcreteAspectTarget(t *testing.T) {
	t.Parallel()

	err := errorchain.NewWithMessage(errTest1, "foo").
		WithAspects(&errCtx{})

	var (
		value  *errCtx
		target any = &value
	)

	require.PanicsWithValue(t,
		"errors: *target must be interface or implement error",
		func() {
			errors.As(err, target)
		},
	)
}

func TestErrorChainErrorAsFindsWrappedError(t *testing.T) {
	t.Parallel()

	type Barer interface{ Bar() string }

	errTest := &testError{}

	err := errorchain.NewWithMessage(errTest, "foo").
		CausedBy(errTest2)

	var barer Barer
	require.ErrorAs(t, err, &barer)
	assert.Equal(t, "bar", barer.Bar())
}

func TestErrorChainUnwrapWithoutCauseReturnsNil(t *testing.T) {
	t.Parallel()

	err := errorchain.New(errTest1)

	assert.NoError(t, errors.Unwrap(err))
}

func TestErrorChainAsIgnoresNilAspect(t *testing.T) {
	t.Parallel()

	type Fooer interface{ Foo() string }

	err := errorchain.New(errTest1).
		WithAspects(nil, &errCtx{})

	var fooer Fooer
	require.ErrorAs(t, err, &fooer)
	assert.Equal(t, "foo", fooer.Foo())
}

func TestErrorChainAsIgnoresNonAssignableAspect(t *testing.T) {
	t.Parallel()

	type Fooer interface{ Foo() string }

	err := errorchain.New(errTest1).
		WithAspects(errTest2, &errCtx{})

	var fooer Fooer
	require.ErrorAs(t, err, &fooer)
	assert.Equal(t, "foo", fooer.Foo())
}

func TestErrorChainErrorAsPrefersAspectOverWrappedError(t *testing.T) {
	t.Parallel()

	type Barer interface{ Bar() string }

	err := errorchain.NewWithMessage(&testError{}, "foo").
		WithAspects(&barAspect{})

	var barer Barer
	require.ErrorAs(t, err, &barer)
	assert.Equal(t, "aspect bar", barer.Bar())
}

func TestErrorChainString(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err  *errorchain.ErrorChain
		want string
	}{
		"short error stack with top level error message": {
			err: errorchain.NewWithMessage(errors.New("resulting error"), "top level error message").
				CausedBy(errors.New("cause error")),
			want: `resulting error: top level error message`,
		},
		"short error stack without top level error message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errors.New("cause error")),
			want: `resulting error: cause error`,
		},
		"longer error stack with top level error message": {
			err: errorchain.NewWithMessage(errors.New("resulting error"), "top level error message").
				CausedBy(errors.New("cause error")).
				CausedBy(errors.New("deeper cause error")),
			want: `resulting error: top level error message`,
		},
		"longer error stack with mid-level error with message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.NewWithMessage(errors.New("cause error"), "mid level error message")).
				CausedBy(errors.New("deeper cause error")),
			want: `resulting error: mid level error message`,
		},
		"longer error stack with mid-level error cause message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.New(errors.New("cause error")).
					CausedBy(errors.New("some error"))).
				CausedBy(errors.New("deeper cause error")),
			want: `resulting error: some error`,
		},
		"longer error stack with tail-level error with message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.New(errors.New("cause error"))).
				CausedBy(errors.New("deeper cause error")),
			want: `resulting error: deeper cause error`,
		},
		"error without detail message": {
			err:  errorchain.New(errors.New("resulting error")),
			want: `resulting error: resulting error`,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, tc.err.String())
		})
	}
}

func TestErrorChainJSONMarshal(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err  error
		want string
	}{
		"short error stack with top level error message": {
			err: errorchain.NewWithMessage(errors.New("resulting error"), "top level error message").
				CausedBy(errors.New("cause error")),
			want: `{"code":"resultingError","message":"top level error message"}`,
		},
		"short error stack without top level error message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errors.New("cause error")),
			want: `{"code":"resultingError","message":"cause error"}`,
		},
		"longer error stack with top level error message": {
			err: errorchain.NewWithMessage(errors.New("resulting error"), "top level error message").
				CausedBy(errors.New("cause error")).
				CausedBy(errors.New("deeper cause error")),
			want: `{"code":"resultingError","message":"top level error message"}`,
		},
		"longer error stack with mid-level error with message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.NewWithMessage(errors.New("cause error"), "mid level error message")).
				CausedBy(errors.New("deeper cause error")),
			want: `{"code":"resultingError","message":"mid level error message"}`,
		},
		"longer error stack with mid-level error cause message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.New(errors.New("cause error")).
					CausedBy(errors.New("some error"))).
				CausedBy(errors.New("deeper cause error")),
			want: `{"code":"resultingError","message":"some error"}`,
		},
		"longer error stack with tail-level error with message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.New(errors.New("cause error"))).
				CausedBy(errors.New("deeper cause error")),
			want: `{"code":"resultingError","message":"deeper cause error"}`,
		},
		"error without detail message": {
			err:  errorchain.New(errors.New("resulting error")),
			want: `{"code":"resultingError","message":"resulting error"}`,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			res, err := json.Marshal(tc.err)

			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(res))
		})
	}
}

func TestErrorChainXMLMarshal(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		err  error
		want string
	}{
		"short error stack with top level error message": {
			err: errorchain.NewWithMessage(errors.New("resulting error"), "top level error message").
				CausedBy(errors.New("cause error")),
			want: `<error><code>resultingError</code><message>top level error message</message></error>`,
		},
		"short error stack without top level error message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errors.New("cause error")),
			want: `<error><code>resultingError</code><message>cause error</message></error>`,
		},
		"longer error stack with top level error message": {
			err: errorchain.NewWithMessage(errors.New("resulting error"), "top level error message").
				CausedBy(errors.New("cause error")).
				CausedBy(errors.New("deeper cause error")),
			want: `<error><code>resultingError</code><message>top level error message</message></error>`,
		},
		"longer error stack with mid-level error with message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.NewWithMessage(errors.New("cause error"), "mid level error message")).
				CausedBy(errors.New("deeper cause error")),
			want: `<error><code>resultingError</code><message>mid level error message</message></error>`,
		},
		"longer error stack with mid-level error cause message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.New(errors.New("cause error")).
					CausedBy(errors.New("some error"))).
				CausedBy(errors.New("deeper cause error")),
			want: `<error><code>resultingError</code><message>some error</message></error>`,
		},
		"longer error stack with tail-level error with message": {
			err: errorchain.New(errors.New("resulting error")).
				CausedBy(errorchain.New(errors.New("cause error"))).
				CausedBy(errors.New("deeper cause error")),
			want: `<error><code>resultingError</code><message>deeper cause error</message></error>`,
		},
		"error without detail message": {
			err:  errorchain.New(errors.New("resulting error")),
			want: `<error><code>resultingError</code><message>resulting error</message></error>`,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			res, err := xml.Marshal(tc.err)

			require.NoError(t, err)
			assert.Equal(t, tc.want, string(res))
		})
	}

	t.Run("uses top level error code and message", func(t *testing.T) {
		t.Parallel()

		testErr := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

		res, err := xml.Marshal(testErr)

		require.NoError(t, err)
		assert.Equal(t, `<error><code>testError1</code><message>foo</message></error>`, string(res))
	})
}
