package errorchain_test

import (
	"encoding/xml"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	errTest1 = errors.New("test error 1")
	errTest2 = errors.New("test error 2")
)

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

func TestCreateErrorWithCause(t *testing.T) {
	t.Parallel()

	// WHEN
	err := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	// THEN
	require.Error(t, err)
	assert.ErrorIs(t, err, errTest1)
	assert.ErrorIs(t, err, errTest2)
	assert.Equal(t, err.Error(), errTest1.Error()+": foo: "+errTest2.Error())

	errs := err.Errors()
	assert.ElementsMatch(t, errs, []error{errTest1, errTest2})
}

func TestErrorChainJSONMarshal(t *testing.T) {
	t.Parallel()

	// GIVEN
	testErr := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	// WHEN
	res, err := testErr.MarshalJSON()

	// THEN
	require.NoError(t, err)
	assert.JSONEq(t, `{"message":"test error 1","details":"foo"}`, string(res))
}

func TestErrorChainXMLMarshal(t *testing.T) {
	t.Parallel()

	// GIVEN
	testErr := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	// WHEN
	res, err := xml.Marshal(testErr)

	// THEN
	require.NoError(t, err)
	assert.Equal(t, `<error><message>test error 1</message><details>foo</details></error>`, string(res))
}
