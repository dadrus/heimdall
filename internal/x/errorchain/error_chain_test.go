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

func (e *errCtx) Foo() string {
	return "foo"
}

type errTest3 struct{}

func (e *errTest3) Error() string {
	return "test error 3"
}

func (e *errTest3) Bar() string {
	return "bar"
}

func TestErrorChainNew(t *testing.T) {
	t.Parallel()

	// WHEN
	err := errorchain.New(errTest1)

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, errTest1)
	assert.Equal(t, err.Error(), errTest1.Error())
}

func TestErrorChainNewWithMessage(t *testing.T) {
	t.Parallel()

	// WHEN
	err := errorchain.NewWithMessage(errTest1, "foobar")

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, errTest1)
	assert.Equal(t, err.Error(), errTest1.Error()+": foobar")
}

func TestErrorChainNewWithFormattedMessage(t *testing.T) {
	t.Parallel()

	// WHEN
	err := errorchain.NewWithMessagef(errTest1, "%s%s", "foo", "bar")

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, errTest1)
	assert.Equal(t, err.Error(), errTest1.Error()+": foobar")
}

func TestErrorChainNewWithCause(t *testing.T) {
	t.Parallel()

	// GIVEN
	type Fooer interface{ Foo() string }

	var fooer Fooer

	// WHEN
	err := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, errTest1)
	assert.ErrorIs(t, err, errTest2)
	assert.Equal(t, err.Error(), errTest1.Error()+": foo: "+errTest2.Error())

	errs := err.Errors()
	assert.ElementsMatch(t, errs, []error{errTest1, errTest2})

	require.False(t, errors.As(err, &fooer))
}

func TestErrorChainNewWithCauseAndContextDetachedFromError(t *testing.T) {
	t.Parallel()
	// GIVEN
	type Fooer interface{ Foo() string }

	var fooer Fooer

	// WHEN
	err := errorchain.NewWithMessage(errTest1, "foo").
		WithErrorContext(&errCtx{}).
		CausedBy(errTest2)

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, errTest1)
	assert.ErrorIs(t, err, errTest2)
	assert.Equal(t, err.Error(), errTest1.Error()+": foo: "+errTest2.Error())

	errs := err.Errors()
	assert.ElementsMatch(t, errs, []error{errTest1, errTest2})

	require.True(t, errors.As(err, &fooer))
	assert.Equal(t, "foo", fooer.Foo())
}

func TestErrorChainNewWithCauseAndContextAttachedToError(t *testing.T) {
	t.Parallel()
	// GIVEN
	type Barer interface{ Bar() string }

	var barer Barer

	errTest := &errTest3{}

	// WHEN
	err := errorchain.NewWithMessage(errTest, "foo").
		CausedBy(errTest2)

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, errTest)
	assert.ErrorIs(t, err, errTest2)
	assert.Equal(t, err.Error(), errTest.Error()+": foo: "+errTest2.Error())

	errs := err.Errors()
	assert.ElementsMatch(t, errs, []error{errTest, errTest2})

	require.True(t, errors.As(err, &barer))
	assert.Equal(t, "bar", barer.Bar())
}

func TestErrorChainJSONMarshal(t *testing.T) {
	t.Parallel()

	// GIVEN
	testErr := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	// WHEN
	res, err := json.Marshal(testErr)

	// THEN
	require.NoError(t, err)
	assert.JSONEq(t, `{"code":"testError1","message":"foo"}`, string(res))
}

func TestErrorChainXMLMarshal(t *testing.T) {
	t.Parallel()

	// GIVEN
	testErr := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	// WHEN
	res, err := xml.Marshal(testErr)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, `<error><code>testError1</code><message>foo</message></error>`, string(res))
}
