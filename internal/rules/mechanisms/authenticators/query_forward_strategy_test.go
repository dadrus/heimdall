package authenticators

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators/extractors/mocks"
)

func TestQueryForwardStrategyApply(t *testing.T) {
	t.Parallel()

	// GIVEN
	ad := mocks.NewAuthDataMock(t)
	ad.EXPECT().Value().Return("Foo")

	strategy := QueryForwardStrategy{Name: "token"}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://test.com", nil)
	require.NoError(t, err)

	// WHEN
	strategy.Apply(ad, req)

	// THEN
	assert.Equal(t, "Foo", req.URL.Query().Get("token"))
}
