package authenticators

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
)

func TestDefaultForwardStrategyApply(t *testing.T) {
	t.Parallel()

	// GIVEN
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test.com", nil)
	require.NoError(t, err)

	ad := mocks.NewAuthDataMock(t)
	ad.EXPECT().ApplyTo(req)

	strategy := DefaultForwardStrategy{}

	// WHEN & THEN expectations are met
	strategy.Apply(ad, req)
}
