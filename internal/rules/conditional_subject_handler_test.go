package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestConditionalSubjectHandlerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		configureMocks func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock)
		assert         func(t *testing.T, err error)
	}{
		{
			uc: "executes if can",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecute(mock.Anything, mock.Anything).Return(true, nil)
				h.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "does not execute if can not",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecute(mock.Anything, mock.Anything).Return(false, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "does not execute if can check fails",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.SubjectHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecute(mock.Anything, mock.Anything).Return(true, testsupport.ErrTestPurpose)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, testsupport.ErrTestPurpose)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			condition := rulemocks.NewExecutionConditionMock(t)
			handler := rulemocks.NewSubjectHandlerMock(t)
			decorator := conditionalSubjectHandler{c: condition, h: handler}

			tc.configureMocks(t, condition, handler)

			// WHEN
			err := decorator.Execute(nil, nil)

			// THEN
			tc.assert(t, err)
		})
	}
}

func TestConditionalSubjectHandlerContinueOnError(t *testing.T) {
	t.Parallel()

	// GIVEN
	handler := rulemocks.NewSubjectHandlerMock(t)
	decorator := conditionalSubjectHandler{c: nil, h: handler}

	handler.EXPECT().ContinueOnError().Return(true)

	// WHEN
	ok := decorator.ContinueOnError()

	// THEN
	assert.True(t, ok)
}
