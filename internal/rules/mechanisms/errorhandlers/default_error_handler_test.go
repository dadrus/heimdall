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

package errorhandlers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
)

func TestDefaultErrorHandlerExecution(t *testing.T) {
	t.Parallel()

	// GIVEN
	ctx := mocks.NewContextMock(t)
	ctx.EXPECT().AppContext().Return(context.Background())
	ctx.EXPECT().SetPipelineError(heimdall.ErrConfiguration)

	errorHandler := newDefaultErrorHandler("foo")

	// WHEN
	wasHandled, err := errorHandler.Execute(ctx, heimdall.ErrConfiguration)

	// THEN
	assert.True(t, wasHandled)
	assert.NoError(t, err)
}

func TestDefaultErrorHandlerPrototype(t *testing.T) {
	t.Parallel()

	// GIVEN
	prototype := newDefaultErrorHandler("foo")

	// WHEN
	eh1, err1 := prototype.WithConfig(nil)
	eh2, err2 := prototype.WithConfig(map[string]any{"foo": "bar"})

	// THEN
	assert.NoError(t, err1)
	assert.Equal(t, prototype, eh1)

	assert.NoError(t, err2)
	assert.Equal(t, prototype, eh2)
	assert.Equal(t, "foo", prototype.HandlerID())
}
