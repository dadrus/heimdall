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

type testError struct{}

func (e *testError) Error() string {
	return "test error 3"
}

func (e *testError) Bar() string {
	return "bar"
}

func TestErrorChainNew(t *testing.T) {
	t.Parallel()

	// WHEN
	err := errorchain.New(errTest1)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, errTest1)
	assert.Equal(t, err.Error(), errTest1.Error())
	assert.Nil(t, err.ErrorContext())
}

func TestErrorChainNewWithMessage(t *testing.T) {
	t.Parallel()

	// WHEN
	err := errorchain.NewWithMessage(errTest1, "foobar")

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, errTest1)
	assert.Equal(t, err.Error(), errTest1.Error()+": foobar")
	assert.Nil(t, err.ErrorContext())
}

func TestErrorChainNewWithFormattedMessage(t *testing.T) {
	t.Parallel()

	// WHEN
	err := errorchain.NewWithMessagef(errTest1, "%s%s", "foo", "bar")

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, errTest1)
	assert.Equal(t, err.Error(), errTest1.Error()+": foobar")
	assert.Nil(t, err.ErrorContext())
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
	require.ErrorIs(t, err, errTest1)
	require.ErrorIs(t, err, errTest2)
	assert.Equal(t, err.Error(), errTest1.Error()+": foo: "+errTest2.Error())
	assert.Nil(t, err.ErrorContext())

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
	require.ErrorIs(t, err, errTest1)
	require.ErrorIs(t, err, errTest2)
	assert.Equal(t, err.Error(), errTest1.Error()+": foo: "+errTest2.Error())
	assert.Equal(t, &errCtx{}, err.ErrorContext())

	errs := err.Errors()
	assert.ElementsMatch(t, errs, []error{errTest1, errTest2})

	require.ErrorAs(t, err, &fooer)
	assert.Equal(t, "foo", fooer.Foo())
}

func TestErrorChainNewWithCauseAndContextAttachedToError(t *testing.T) {
	t.Parallel()
	// GIVEN
	type Barer interface{ Bar() string }

	var barer Barer

	errTest := &testError{}

	// WHEN
	err := errorchain.NewWithMessage(errTest, "foo").
		CausedBy(errTest2)

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, errTest)
	require.ErrorIs(t, err, errTest2)
	assert.Equal(t, err.Error(), errTest.Error()+": foo: "+errTest2.Error())
	assert.Nil(t, err.ErrorContext())

	errs := err.Errors()
	assert.ElementsMatch(t, errs, []error{errTest, errTest2})

	require.ErrorAs(t, err, &barer)
	assert.Equal(t, "bar", barer.Bar())
}

func TestErrorChainAsUsedWithConcreteType(t *testing.T) {
	t.Parallel()
	// GIVEN
	type Barer struct{}

	var barer Barer

	errTest := &testError{}

	err := errorchain.NewWithMessage(errTest, "foo").
		WithErrorContext(errTest2)

	defer func() { recover() }()

	// WHEN
	err.As(&barer)

	// THEN
	t.Errorf("should have panicked")
}

func TestErrorChainAsUsedWithNotAssignableInterface(t *testing.T) {
	t.Parallel()
	// GIVEN
	type Barer interface{ Foo() string }

	var barer Barer

	errTest := &testError{}

	err := errorchain.NewWithMessage(errTest, "foo").
		WithErrorContext(errTest2)

	// WHEN
	res := err.As(&barer)

	// THEN
	assert.False(t, res)
}

func TestErrorChainString(t *testing.T) {
	t.Parallel()

	// GIVEN
	testErr := errorchain.NewWithMessage(errTest1, "foo").CausedBy(errTest2)

	// WHEN
	value := testErr.String()

	// THEN
	assert.Equal(t, "test error 1: foo", value)
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
