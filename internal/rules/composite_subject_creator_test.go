package rules

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/pipeline/subject"
	"github.com/dadrus/heimdall/internal/testsupport"
)

func TestCompositeAuthenticatorExecutionWithFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	sub := &subject.Subject{ID: "foo"}

	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth1 := &mockSubjectCreator{}
	auth1.On("Execute", ctx).Return(nil, testsupport.ErrTestPurpose)

	auth2 := &mockSubjectCreator{}
	auth2.On("Execute", ctx).Return(sub, nil)

	auth := compositeSubjectCreator{auth1, auth2}

	// WHEN
	rSub, err := auth.Execute(ctx)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, sub, rSub)

	auth1.AssertExpectations(t)
	auth2.AssertExpectations(t)
}

func TestCompositeAuthenticatorExecutionWithoutFallback(t *testing.T) {
	t.Parallel()

	// GIVEN
	sub := &subject.Subject{ID: "foo"}

	ctx := &mocks.MockContext{}
	ctx.On("AppContext").Return(context.Background())

	auth1 := &mockSubjectCreator{}
	auth2 := &mockSubjectCreator{}
	auth2.On("Execute", ctx).Return(sub, nil)

	auth := compositeSubjectCreator{auth2, auth1}

	// WHEN
	rSub, err := auth.Execute(ctx)

	// THEN
	assert.NoError(t, err)

	assert.Equal(t, sub, rSub)

	auth1.AssertExpectations(t)
	auth2.AssertExpectations(t)
}
