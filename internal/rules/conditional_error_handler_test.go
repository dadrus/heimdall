package rules

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	rulemocks "github.com/dadrus/heimdall/internal/rules/mocks"
)

func TestConditionalErrorHandlerExecute(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc             string
		configureMocks func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.ErrorHandlerMock)
		assert         func(t *testing.T, err error)
	}{
		{
			uc: "executes if can",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.ErrorHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecuteOnError(mock.Anything, mock.Anything).Return(true, nil)
				h.EXPECT().Execute(mock.Anything, mock.Anything).Return(nil)
				h.EXPECT().ID().Return("test")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "does not execute if can not",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.ErrorHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecuteOnError(mock.Anything, mock.Anything).Return(false, nil)
				h.EXPECT().ID().Return("test")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errErrorHandlerNotApplicable)
			},
		},
		{
			uc: "does not execute if can check fails",
			configureMocks: func(t *testing.T, c *rulemocks.ExecutionConditionMock, h *rulemocks.ErrorHandlerMock) {
				t.Helper()

				c.EXPECT().CanExecuteOnError(mock.Anything, mock.Anything).
					Return(true, errors.New("some error"))
				h.EXPECT().ID().Return("test")
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "some error")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			condition := rulemocks.NewExecutionConditionMock(t)
			handler := rulemocks.NewErrorHandlerMock(t)
			decorator := conditionalErrorHandler{c: condition, h: handler}

			ctx := mocks.NewContextMock(t)
			ctx.EXPECT().AppContext().Return(context.Background())

			tc.configureMocks(t, condition, handler)

			// WHEN
			err := decorator.Execute(ctx, errors.New("test error"))

			// THEN
			tc.assert(t, err)
		})
	}
}
