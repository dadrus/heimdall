// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package exporters

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/trace"
)

func TestRegistryEmptyStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}

	// WHEN
	err := r.store("first", func(_ context.Context) (trace.SpanExporter, error) { return nil, errors.New("test error") })

	// THEN
	require.NoError(t, err)
}

func TestRegistryNonEmptyStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}
	require.NoError(t, r.store("first", func(_ context.Context) (trace.SpanExporter, error) { return nil, errors.New("test error") }))

	// WHEN
	err := r.store("second", func(_ context.Context) (trace.SpanExporter, error) { return nil, errors.New("test error") })

	// THEN
	require.NoError(t, err)
}

func TestRegistryDuplicateStore(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}
	require.NoError(t, r.store("first", func(_ context.Context) (trace.SpanExporter, error) { return nil, errors.New("test error") }))

	// WHEN
	err := r.store("first", func(_ context.Context) (trace.SpanExporter, error) { return nil, errors.New("test error") })

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicateRegistration)
	assert.Contains(t, err.Error(), "first")
}

func TestRegistryEmptyLoad(t *testing.T) {
	t.Parallel()

	// GIVEN
	r := registry[trace.SpanExporter]{}

	// WHEN
	v, ok := r.load("non-existent")

	// THEN
	assert.False(t, ok, "empty registry should hold nothing")
	assert.Nil(t, v, "non-nil executor factory returned")
}

func TestRegistryExistentLoad(t *testing.T) {
	t.Parallel()

	// GIVEN
	reg := registry[trace.SpanExporter]{}

	require.NoError(t, reg.store("existent",
		func(_ context.Context) (trace.SpanExporter, error) { return nil, errors.New("for test purpose") }))

	// WHEN
	value, ok := reg.load("existent")

	// THEN
	assert.True(t, ok, "registry should hold expected factory")
	assert.NotNil(t, value)

	_, err := value(context.Background())
	assert.Contains(t, err.Error(), "for test purpose")
}
